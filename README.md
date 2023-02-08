# DistributedIBE
This library implements distributed IBE scheme based on Boneh-Franklin scheme. 
## Security Parameters
This scheme relies on the hybrid encryption. We use the implementation of such scheme by `FiloSottile/age` which only encrypts a random symmetric key that is used to actually symmetrically encrypt the data using `Chacha20Poly1305`.

The used symmetric key is of size `32` bytes. The implementation of IBE scheme used to encrypt this key uses the `BLS12-381` curve.

## Benchmarking Results
We have tested the efficiency of our scheme against the number of validators and message size. 

The below table shows the runtime of the scheme covering share generation, key extraction, commitment verification, message encryption, key aggregation, and ciphertext decryption through different numbers of validators:

| Number of Validators  |           Execution Time    |
| -------------         | ------------- |
|  4                    |        10880689 ns/op       |
|    8                 |             19333171 ns/op  |
|    16                 |             36199305 ns/op  |
|    32                 |             70639750 ns/op  |
|    64                 |             144968458 ns/op  |
|    128                 |             290355378 ns/op  |

Based on the above table, we can clearly see that the executrion time increases linearly with the number of validators.

Since the message is being encrypted first and the key is used for the IBE, we expect the execution time to be independent of the message size. The microbenchmarking results confirm this as shown in the below table:

| Message Size (bytes)  |           Execution Time    |
| -------------         | ------------- |
|  8                   |        11180636 ns/op       |
|    32                 |             11006738 ns/op  |
|    128                 |             11160579 ns/op  |
|    512                 |             10927982 ns/op  |
|    2048                |             10927359 ns/op  |
|    8192                |             11029081 ns/op  |

## Configuration
The following commands install the required packages and dependancies:
```sh
go mod init DistributedIBE
go mod tidy
```
## Testing
Use the following commands to run the sample test:
```sh
cd DistributedIBE
go test
```
Use the below commands to run the benchmarks:
```sh
cd DistributedIBE
go test --bench=.
```
