#!/bin/bash

#
# make_ca_bundle_simple
# ---------------------
# Build a CA bundle from a server’s presented chain, with one AIA fetch fallback.
#
# Params:
#   $1 = host[:port]  (port defaults to 443)
#   $2 = output path  (optional, default: ca-bundle.pem)
# Returns:
#   Writes the bundle to $2 (or ca-bundle.pem). Exits non-zero on hard errors.
#
make_ca_bundle() 
{
	local host="$1"
	local port="$2"
	local out="$3"


	# 1) Grab the full chain the server presents
	openssl s_client -showcerts -servername "$host" -connect "$host:$port" </dev/null 2>/dev/null \
		| sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' > chain.pem

	# 2) Split into cert01.pem, cert02.pem, ...
	rm -f cert*.pem || true
	awk 'BEGIN{n=0} /BEGIN CERTIFICATE/{n++; fn=sprintf("cert%02d.pem", n)} {print > fn} /END CERTIFICATE/{close(fn)}' chain.pem

	# 3) Build CA bundle from any CA:TRUE certs in the chain
	rm -f "$out" || true
	for f in cert*.pem
	do
		if openssl x509 -in "$f" -noout -text | grep -q "CA:TRUE"
		then
			cat "$f" >> "$out"
		fi
	done

	# 4) If bundle is empty, fetch the issuer once via AIA from the leaf
	if [[ ! -s "$out" ]]
	then
		local issuer_url="$(openssl x509 -in cert01.pem -noout -text | awk -F'URI:' '/CA Issuers/{print $2}' | head -n1 | tr -d ' ' || true)"
		if [[ -n "${issuer_url:-}" ]]
		then
			curl -fsSL "$issuer_url" -o issuer.der
			openssl x509 -inform DER -in issuer.der -out issuer.pem
			if openssl x509 -in issuer.pem -noout -text | grep -q "CA:TRUE"
			then
				cat issuer.pem >> "$out"
			fi
		fi
	fi

	# 5) Sanity check
	if [[ -s "$out" ]]
	then
		openssl verify -CAfile "$out" cert01.pem >/dev/null 2>&1 || true
		echo "Wrote CA bundle: $out"
	else
		echo "No CA certs found (chain didn’t include CA and AIA fetch failed). Bundle not created." >&2
		return 3
	fi
}


main()
{
	./setup.sh


	set -x

	source cicd/cs-workflow-rc
	export OS_CACERT=$HOME/ca-bundle.pem
	make_ca_bundle 10.246.114.81 5000 $OS_CACERT

	# clean out any old openstack servers, etc.
	# this project is for CICD only.
	python3 cicd/purge-openstack.py

	# add the CICD-only "private" key.
	chmod 600 cicd/id_rsa
	eval "$(ssh-agent -s)"
	ssh-add cicd/id_rsa

	# setup OS_CACERT for python
	cat "$OS_CACERT" >> "$(python3 -m certifi)"

	./deploy-nodes.py -c cloud-configs/axes-cicd.json -e enterprise-configs/dc-cs-fs-moodle.json  || exit 1
	./post-deploy.py deploy-output.json || exit 1
	./simulate-logins.py user-roles/user-roles.json enterprise-configs/dc-cs-fs-moodle.json post-deploy-output.json || exit 1
	timeout 300 ./emulate-logins.py post-deploy-output.json logins.json  --fast-debug --workflows moodle build_software browse_iis 2>&1 |tee el.out
	if [[ ${PIPESTATUS[0]} -ne 124 ]]
	then
		echo 'Emulate logins exited before 300 seconds'
		exit 1
	fi
	./cleanup-nodes.py deploy-output.json || exit 1


	# purge any extra stuff that cleanup didn't do.
#	python3 cicd/purge-openstack.py
	exit 0


}

main "$@"
