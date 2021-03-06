#PII Search Tool
Written by: Zach Varnell

DISCLAIMER: This tool is for testing and educational purposes only and can only be used where consent has been given.

### Setup
Mac (with Homebrew)

```
brew install libmagic
brew link libmagic
```
Ubuntu / Debian

```
apt-get install libmagic-dev
```

Both

```
bundle install
```

### Usage
```
ruby pii.rb /path/to/search/
```

### Tested on
Mac OS X - Ruby 1.9.3

Debian 7 - Ruby 1.9.3

Ubuntu 12.04.4 LTS - Ruby 1.9.3

### Known Bugs / Issues
- Works best when run on a defined set of files (e.g. ```ruby pii.rb /Users/zach/Documents/``` rather than ```ruby pii.rb /```.

- There tend to be a high number of false positives with Social Security numbers. I need to adjust the regex for this.

- May crash on certain filetypes.

- Only searches plan text files, Office documents, and PDFs right now. I plan to expand the filetype support. 

### Bugs / Enhancements
For bug reports or enhancements, please open an issue here: https://github.com/zvarnell/pii-search/issues