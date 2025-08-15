# DistributedIBE
This library implements the Threshold IBE scheme based on Boneh-Franklin scheme. 
## Security Parameters
This scheme relies on the hybrid encryption. We use the implementation of such scheme by `FiloSottile/age` which only encrypts a random symmetric key that is used to encrypt the data using `Chacha20Poly1305`.

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

We also broke down the steps to measure the overhead of each stage:
|  Function |  Number of Validators  |           Execution Time    |
|--------| -------------         | ------------- |
|     Key extraction and aggregation    |  128                   |      213753903 ns/op       |

|  Function |  Number of messages  |           Execution Time    |
|--------| -------------         | ------------- |
|     Encryption   |  1                   |      1574796 ns/op       |
|         |  4                   |      6179149 ns/op       |
|        |  16                   |      24764695 ns/op       |
|        |  64                   |      100275889 ns/op       |
|         |  256                   |      399253311 ns/op       |
|     Decryption    |  8                   |      7205781 ns/op       |
|        |  32                   |      30806709 ns/op       |
|     |  128                   |      117187771 ns/op       |
|        |  512                   |      457499724 ns/op       |
|        |  1024                   |      930084488 ns/op       |

| Message Size (bytes)  |           Encryption Time    |
| -------------         | ------------- |
|  8                   |      1418055 ns/op       |
|    32                 |      1357339 ns/op       |
|    128                 |      1396858 ns/op       |
|    512                 |      1385265 ns/op       |
|    2048                |      1410541 ns/op       |
|    8192                |      1356855 ns/op       |
|    32768               |      1406723 ns/op       |
|    131072              |      1412484 ns/op       |
|    524288              |      1385327 ns/op       |
|    1048576             |      1369466 ns/op       |
|    10485760            |      1390764 ns/op       |
|    104857600           |      1411491 ns/op       |

|  Function |  Number of Validators  |           Execution Time    |
|--------| -------------         | ------------- |
|     Aggregation     |  4                   |      5181942 ns/op       |
|         |  8                   |      10590690 ns/op       |
|        |  16                   |      22940430 ns/op       |
|        |  32                   |      45536602 ns/op       |
|        |  64                   |      94044122 ns/op       |
|        |  128                   |      179813664 ns/op       |
|        |  256                   |      377430191 ns/op       |
|        |  512                   |      771633934 ns/op       |
|        |  1024                   |      1682627333 ns/op       |

| Message Size (bytes)  |           Decryption Time    |
| -------------         | ------------- |
|  8                   |      689101 ns/op       |
|    32                 |      687388 ns/op       |
|    128                 |      728981 ns/op       |
|    512                 |      723354 ns/op       |
|    2048                |      698191 ns/op       |
|    8192                |      719345 ns/op       |
|    32768               |      716769 ns/op       |
|    131072              |      873302 ns/op       |

In order to improve the efficiency in case of decrypting large number of messages, we can perform the decryption in parallel. Below shows the execution times for the parallel decryption:
|  Function |  Number of messages  |           Execution Time    |
|--------| -------------         | ------------- |
|     Decryption    |  8                   |      2404587 ns/op       |
|        |  32                   |      6470264 ns/op       |
|     |  128                   |      23466097 ns/op       |
|        |  512                   |      80075636 ns/op       |
|        |  1024                   |      153275583 ns/op       |

All benchmarks have been ran on a laptop with 12th Gen Intel(R) Core(TM) i7-1270P cpu.
### KZG Commitments vs VSS
Below, we compare the verification time for KZG commitments vs VSS.
|  Function |  Number of Validators  |           Execution Time    |
|--------| -------------         | ------------- |
|    KZG Share Verification    |  4                   |      4744239 ns/op       |
|        |  8                   |      9348084 ns/op       |
|     |  16                   |      18922709 ns/op       |
|        |  32                   |      38153229 ns/op       |
|        |  64                   |      77705447 ns/op       |
|        |  128                   |      154309057 ns/op       |
|    VSS Share Verification    |  4                   |      383691 ns/op       |
|        |  8                   |      1521771 ns/op       |
|     |  16                   |      7168398 ns/op       |
|        |  32                   |      38691278 ns/op       |
|        |  64                   |      219296811 ns/op       |
|        |  128                   |      1039926768 ns/op       |
|    KZG Share Generation    |  4                   |      641104 ns/op       |
|        |  8                   |      2612382 ns/op       |
|     |  16                   |      11231675 ns/op       |
|        |  32                   |      52606951 ns/op       |
|        |  64                   |      260647892 ns/op       |
|        |  128                   |      1075045566 ns/op       |
|    VSS Share Generation    |  4                   |      191175 ns/op       |
|        |  8                   |      332393 ns/op       |
|     |  16                   |      610982 ns/op       |
|        |  32                   |      1264965 ns/op       |
|        |  64                   |      2662454 ns/op       |
|        |  128                   |      7105321 ns/op       |


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
