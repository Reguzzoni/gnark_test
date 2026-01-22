Comprensione documentazione consensys gnark


Schemes curves gnark
https://docs.gnark.consensys.io/Concepts/schemes_curves
BN254 in zsnark_BN254
No quantum safe

Comprendere MiMC
https://eprint.iacr.org/2016/492.pdf
Comprendere se quatum proof

Valutazione Poseidon come hash function dello ZKP
https://eprint.iacr.org/2019/458.pdf

Next TODO check quantum proof RLWE-based o Stark

Come eseguire MiMC

-- mandatorio avere golang
cd zsnark_MiMC 
go run main.go

-- verranno prodotti i file proof.json, public.json e verification_key.json
-- spostare i file proof.json, public.json e verification_key.json in testsnarkjs
cd testSnartJS
npm install
npm run verify
