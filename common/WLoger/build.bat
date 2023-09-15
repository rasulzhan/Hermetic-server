mkdir build & ^
cd build && rm -rf * & ^
mkdir build & ^
cd build && rm -rf * & ^
cmake ../../ -DCMAKE_BUILD_TYPE=Release && ^ 
cmake --build . & ^
cd ../../
build\test.exe