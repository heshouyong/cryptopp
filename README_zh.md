
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
 CXX=aarch64-linux-gnu-g++ CXXFLAGS="-O2 -fPIC -Wall -shared -pipe -std=c++11" make -f Gnumakefile-cross -j2
 
 make install PREFIX=/path/to/file
 ```




