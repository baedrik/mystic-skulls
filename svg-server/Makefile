all:
	RUSTFLAGS='-C link-arg=-s' cargo build --release --target wasm32-unknown-unknown
	cp ./target/wasm32-unknown-unknown/release/*.wasm ./contract.wasm
	## The following line is not necessary, may work only on linux (extra size optimization)
	# wasm-opt -Os ./contract.wasm -o ./contract.wasm
	cat ./contract.wasm | gzip -9 > ./contract.wasm.gz

clean:
	cargo clean
	-rm -f ./contract.wasm ./contract.wasm.gz

compile-optimized: _compile-optimized contract.wasm.gz
_compile-optimized:
	RUSTFLAGS='-C link-arg=-s' cargo build --release --target wasm32-unknown-unknown --locked
	@# The following line is not necessary, may work only on linux (extra size optimization)
	wasm-opt -Oz ./target/wasm32-unknown-unknown/release/*.wasm -o ./contract.wasm
	
contract.wasm.gz: contract.wasm
	cat ./contract.wasm | gzip -9 > ./contract.wasm.gz