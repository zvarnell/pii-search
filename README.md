#PII Search Tool
Written by: Zach Varnell

DISCLAIMER: This tool is for testing and educational purposes only and can only be used where consent has been given.

### Setup
Mac

```
brew install libmagic
brew link libmagic
```
Ubuntu

```
apt-get install libmagic-dev
```

Both

```
gem install yomu
gem install ruby-filemagic
```

### Usage
```
ruby pii.rb /path/to/search/
```

### Tested on
Mac OS X - Ruby 1.9.3

### Known Bugs / Issues
- Works best when run on a defined set of files (e.g. ```ruby pii.rb /Users/zach/Documents/``` rather than ```ruby pii.rb /```.

- There tend to be a high number of false positives with Social Security numbers. I need to adjust the regex for this.

- May crash on certain filetypes.

- Only searches plan text files, Office documents, and PDFs right now. I plan to expand the filetype support. 
