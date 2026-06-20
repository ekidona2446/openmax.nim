import ../src/openmax/crypto/sha256

const vectors = [
  ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
  ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
  ("000000", "91b4d142823f7d20c5f08df69122de43f35f057a988d9619f6d3138485c9a203")
]

for (input, expected) in vectors:
  let actual = sha256Hex(input)
  doAssert actual == expected, input & ": " & actual & " != " & expected

echo "sha256 selftest ok"
