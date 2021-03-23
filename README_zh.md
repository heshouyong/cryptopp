
# cryptopp　中文使用说明 
* linux 编译与使用
```
git clone https://github.com/heshouyong/cryptopp.git

cd cryptopp

make

cd example

g++ crypto_test.cpp -I.. -L.. -lcryptopp -o crypto_test

./crypto_test
```
* linux arm 交叉编译与使用
  
 ```
CXX=aarch64-linux-gnu-g++ CXXFLAGS="-std=c++11" AR=aarch64-linux-gnu-ar RANLIB=aarch64-linux-gnu-ranlib LD=aarch64-linux-gnu-ld  make -f GNUmakefile-cross -j2
 
 make install PREFIX=/path/to/file
 ```




