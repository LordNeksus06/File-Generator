# File-Generator
Create thousands of files to test the speed of a hdd/ssd

The goal of this project was to  create a file generator that is extremly efficient and perfect for testing storage.
It is completly multithreaded and I reached speeds up to 10GB/s.



You can use the compiled verion in the releases or compile it yourself:

  g++ -std=c++23 -O2 -static -pthread -o file_generator main.cpp





Usage:
  C:\Users\EAGRNDMEAS\Desktop\helloworldCopy\file_generator_win.exe --path <path> --basename <name> --count <number> --size <kb|MB|GB> [--minsize <kb|MB|GB>] [--maxsize <kb|MB|GB>] --mode <r/z/u> [--threads <n>] [--blocksize <kb>] [--ext <.ext>] [--start <n>] [--random-names] [--dry-run] [--hash] [--content-type <ascii|digit|german|hex|bin|special>] [--async] [--pattern <str>] [--cleanup] [--log <file>] [--json] [--debug]
Parameters can be specified in any order.
Example:
  C:\Users\EAGRNDMEAS\Desktop\helloworldCopy\file_generator_win.exe --path /destination/path --basename test --mode r --count 10 --size 400M --threads 10 --blocksize 1k --ext .bin --start 42 --random-names --hash --content-type ascii --async --cleanup

Short options:
  -p  --path         Target directory
  -b  --basename     Base name of the files
  -c  --count        Number of files (file count limit in Windows and Linux --> error)
  -s  --size         File size (e.g. 1024, 1M, 2G)
  --minsize          Minimum file size (range, like --size)
  --maxsize          Maximum file size (range, like --size)
  -m  --mode         'r' for random (Windows), 'z' for zeros, 'u' for /dev/urandom (Linux)
  -t  --threads      (optional) Number of threads
  -B  --blocksize    (optional) Block size in KB (program internal, the amount of data being buffered) (default: 4096 = 4MB)
  -e  --ext          (optional) File extension, e.g. .bin
  -S  --start        (optional) Start index for file names (e.g. start from 3)
  --random-names     (optional) Random file names
  --dry-run          (optional) Only display what would be done
  --hash             (optional) Output SHA256 hash after creation
  --content-type     (optional) ascii, digit, german, hex, bin, special
  --async            (optional) Asynchronous writing
  --pattern          (optional) Pattern string to be written cyclically into the file
  --cleanup          (optional) Delete all generated files after test run
  --log <file>       (optional) Log file for actions and errors, in combination with debug
  --json             (optional) Output statistics as JSON
  --debug            (optional) Additional debug output
  -h  --help         Show this help message
  --histogram         (optional) Show file size histogram in output
