package lib_test

import (
	"strings"
	"testing"

	"github.com/dewaka/license_gen/lib"
)

var privKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAqMIinjpR/FK4qi1Ji7H4OAc63vTRtcbQF5ptcNQdU8w1UkZW
E/F8WfLmmSqRQB1N0JIyoiPM6JanOTD3uZzpJguAlI1vmKBhbawLiID12km5p6ob
A7ML0cx3/dgrEwWqIt4T5WH3kA13bxPptvlud99upzdI+DuQsgXjvbAUZcZYRUZA
57NGjzMhmEbpaUUwgNz4EeACyeGnE/DZ5AlUQXIXu7USP5MyADmjsxTbgdVzBWpO
ipimbQjPUn2VvxDvOFeh/beVEu7lj56b2bNOoSDThBo/or8EUzDRCvanP+03NV6h
iVaoxIhNZWMLIgUjjCZ4mDn7ib4NK46aGL8onQIDAQABAoIBACrkVMokhov8NmVC
Z2vzCuSqqcLbNKXf5ynonSJNNzsCLxc/O0eMXA+8lfGeCRbjm9CEKAxfzwfaqpv1
nzD0+akqyT54iEGhmcG3NaM3K8WUcXR03rLdAgcL0f+ZvrDyAqEkEqh9ct+RHKcF
x6Qy12nuRwCHI6u77/XfW1ft9fE7w5Yl8VdlmpNpFbkr8S574r8aMkyrt569gz6R
NA3dpKZob63d5VZzag93O153niCf7Ndv94lQdYaI7LM8n9fUHyvX3TwE/GadlxIX
HkFOq+nnALPUdjd3QmTxZrOhM0lrTQfI0Dz0o8l4y6GQX6/tzrBYO34ISMJ60Te/
x1xp9l0CgYEA2WWpIF/cujKVg/7T4hUOLQjcRdlH8nZvBedx6TxyjHuIQsTyftWM
L5WUQUv3mQA1fNX1s8gS1pq7qu5zZs8F4xGaEX4msd9jt5Go+7fbptCHYu7Li/rI
351xGV7J8BzJqWdzjnu/y2Jefwaw/ENdRw5EsMx6Xj2gxe27XJS4dzcCgYEAxrl5
sbcs2Fxf/+UhiYchjhTIKcM0uuIVqctnTvj8xqKQRqCzX3JQpkBE+kxjUUmatrTI
pGRPs0gQ//6lZI2HaagF82oXmt2xbB47Ne0snIplPNazGy6luFNEnjC/mO2F6Hbb
EzXXphGq14oktNGRtIe8EVETxx6o3QiaSApcYMsCgYEAtuv7auo+Z824UOBSmKDu
1KXn8j3pc/KDaIxeJMpf+CTZepUNFfvJgSBzJp4tL+glGW1O2H84mqqHzkPlhlQb
t/xPjvh+xpwY45UEgwkpISvFP1F+o8HY048+YwKHGCqg5JHPgcxOjWuv52JR+XEV
Q3yV/82OCU4BwYlPZY8dx/ECgYAPSFRDhoK8YN5BH63kla/O7Wo3S/vSI3DnDe1z
9VH7NKVDyTgCLxhksKydUyKQLcjoJB8KBWzbrL8h8MNnaDrxtSo//fiywDnUxr5m
90ZnA32loB1GCeBUvJKaV8VkTV/u8LUIVSuwactpqAYKodNCvu2Hp2SN+52g4fh7
cdCI4QKBgDIYz+79PtiooF33KHNOIvYoTvcNZIF2stS3hXnzOTz3PIARcTS5GW7J
+DuPVhCgrwmX+lPHR2bib9w0OD8rZZUYD7A356cG3gdNSZCIGZ78Xv/2OeZabnFk
ZWcfJ43BpNXKbnVRjxJ7+93Tr1KSyLJKzozgq6EuHcBq06/yvBf8
-----END RSA PRIVATE KEY-----
`

var pubKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqMIinjpR/FK4qi1Ji7H4
OAc63vTRtcbQF5ptcNQdU8w1UkZWE/F8WfLmmSqRQB1N0JIyoiPM6JanOTD3uZzp
JguAlI1vmKBhbawLiID12km5p6obA7ML0cx3/dgrEwWqIt4T5WH3kA13bxPptvlu
d99upzdI+DuQsgXjvbAUZcZYRUZA57NGjzMhmEbpaUUwgNz4EeACyeGnE/DZ5AlU
QXIXu7USP5MyADmjsxTbgdVzBWpOipimbQjPUn2VvxDvOFeh/beVEu7lj56b2bNO
oSDThBo/or8EUzDRCvanP+03NV6hiVaoxIhNZWMLIgUjjCZ4mDn7ib4NK46aGL8o
nQIDAQAB
-----END PUBLIC KEY-----
`

func TestReadPublicKey(t *testing.T) {
	r := strings.NewReader(pubKey)
	_, err := lib.ReadPublicKey(r)

	if err != nil {
		t.Error("Failed to read public key!")
	}
}

func TestReadPrivateKey(t *testing.T) {
	r := strings.NewReader(privKey)
	_, err := lib.ReadPrivateKey(r)

	if err != nil {
		t.Error("Failed to read private key!")
	}
}
