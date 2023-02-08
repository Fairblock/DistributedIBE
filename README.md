# DistributedIBE
This library implements distributed IBE scheme based on Boneh-Franklin scheme. 
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