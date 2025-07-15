# File-Generator
Create thousands of files to test the speed of a hdd/ssd

The goal of this project was to  create a file generator that is extremly efficient and perfect for testing storage.
It is completly multithreaded and I reached speeds up to 10GB/s.



You can use the compiled verion in the releases or compile it yourself:

  g++ -std=c++23 -O2 -static -pthread -o file_generator main.cpp
