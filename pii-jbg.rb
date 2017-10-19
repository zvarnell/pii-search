#!/usr/bin/env ruby
# PII Search tool
# Zach Varnell

require 'yomu'
require 'ruby-filemagic'

def findpii(f,fname)
    fpatternmatchlog = open("pii-pattern-matches.log","a")
    fantipatternmatchlog = open("pii-antipattern-matches.log","a")
    # Read each line of file
    linecount = 1
    f.each_line do |line|
        # Driver's License Patterns from dl_regex.json
	@dlpatterns.each do |item|
            fpatternmatch =+ 1
	    dlreg = "/" + item[1]['rule'].gsub(/\^/,'').gsub(/\$/,'') + "/"
            if !(match_data = line.scrub('*').match(dlreg)).nil?
                match_data = match_data.to_s
	        fpatternmatchlog.write("[!] DL (" + item[0] + ") found in " + $file + " on line " + linecount.to_s + ": " + match_data.to_s + "\n")
                # we have a match.  now we need to filter out antipatterns
                # loop through anti-patterns, searching for matches
                @apatterns.each do |ap|
	            apreg = "/" + ap[1]['rule'].gsub(/\^/,'').gsub(/\$/,'') + "/"
                    # if anti-pattern doesn't match, continue printing data
                    #puts "[Info] AntiPattern: " + ap[0] + " and Pattern: " + apreg + "\n"
                    if !(line.scrub('*').match(apreg)).nil? 
                        fantipatternmatch =+ 1
                        fantipatternmatchlog.write("[!] DL (" + item[0] + ") found in " + $file + " on line " + linecount.to_s + ": " + match_data + "\n")
                        puts "[!] DL (" + item[0] + ") found in " + $file + " on line " + linecount.to_s + ": " + match_data + "\n"
                    end
                end
	    end
	end
	#puts "[Info] CC Pattern: " + $cc.to_s + "\n"
        if !(match_data = line.scrub('*').match($cc)).nil?
            # we have a match.  now we need to filter out antipatterns
            # loop through anti-patterns, searching for matches
            match_data = match_data.to_s
            fpatternmatch =+ 1
            fpatternmatchlog.write("[!] CC# found in " + $file + " on line " + linecount.to_s + ": " + match_data + "\n") if luhnother(match_data) == true
            @apatterns.each do |ap|
                apreg = "/" + ap[1]['rule'].gsub(/\^/,'').gsub(/\$/,'') + "/"
                #puts "[Info] AntiPattern: " + ap[0] + " and Pattern: " + apreg + "\n"
                # if anti-pattern doesn't match, continue printing data
                if !(line.scrub('*').match(apreg)).nil? 
                    fantipatternmatch =+ 1
                    puts "\r[!] CC# found in " + $file + ": " + match_data + "\n\n" if luhnother(match_data) == true

                    fantipatternmatchlog.write("[!] CC# found in " + $file + " on line " + linecount.to_s + ": " + match_data + "\n") if luhnother(match_data) == true
                    puts "[!] CC# found in " + $file + " on line " + linecount.to_s + ": " + match_data + "\n" if luhnother(match_data) == true
                end
            end
        end
	#puts "[Info] SSN Pattern: " + $ssn.to_s + "\n"
        if !(match_data = line.scrub('*').match($ssn)).nil?
            match_data = match_data.to_s
            # we have a match.  now we need to filter out antipatterns
            # loop through anti-patterns, searching for matches
            fpatternmatch =+ 1
            fpatternmatchlog.write("[!] SSN found in " + $file + " on line " + linecount.to_s + ": " + match_data.to_s + "\n")
            @apatterns.each do |ap|
                apreg = "/" + ap[1]['rule'].gsub(/\^/,'').gsub(/\$/,'') + "/"
                #puts "[Info] AntiPattern: " + ap[0] + " and Pattern: " + apreg + "\n"
                fantipatternmatch =+ 1
                fantipatternmatchlog.write("[Info] AntiPattern: " + ap[0] + " and Pattern: " + apreg + "\n")
                # if anti-pattern doesn't match, continue printing data
                if !(line.scrub('*').match(apreg)).nil? 
                    fantipatternmatchlog.write("[!] SSN found in " + $file + " on line " + linecount.to_s + ": " + match_data + "\n")
                    puts "[!] SSN found in " + $file + " on line " + linecount.to_s + ": " + match_data + "\n"
                end
            end
        end
	linecount += 1
    end
    fpatternmatchlog.close
    fantipatternmatchlog.close
end

# Function to validate credit card numbers
def luhnother(ccNumber)
  ccNumber = ccNumber.gsub(/\d/,'').split(//).collect { |digit| digit.to_i }
  parity = ccNumber.length % 2
  sum = 0
  ccNumber.each_with_index do |digit,index|
    digit = digit * 2 if index%2==parity
    digit = digit - 9 if digit > 9
    sum = sum + digit
  end
  return (sum%10)==0
end

# Checks for major credit card numbers
$cc = /^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})$|^[ -]*(?:4[ -]*(?:\d[ -]*){11}(?:(?:\d[ -]*){3})?\d|5[ -]*[1-5](?:[ -]*[0-9]){14}|6[ -]*(?:0[ -]*1[ -]*1|5[ -]*\d[ -]*\d)(?:[ -]*[0-9]){12}|3[ -]*[47](?:[ -]*[0-9]){13}|3[ -]*(?:0[ -]*[0-5]|[68][ -]*[0-9])(?:[ -]*[0-9]){11}|(?:2[ -]*1[ -]*3[ -]*1|1[ -]*8[ -]*0[ -]*0|3[ -]*5(?:[ -]*[0-9]){3})(?:[ -]*[0-9]){11})[ -]*$/

# Checks for basic SSN format and eliminates some invalid numbers. Will not find Individual Taxpayer Identification Numbers
$ssn = /\b(?!000|666|\A9)(?:[0-6][0-9]{2}|7(?:[0-6][0-9]|7[0-2]))[^\d]?(?!00)[0-9]{2}[^\d]?(?!0000)[0-9]{4}\b/

# Checks for Drivers License Numbers
# https://ntsi.com/drivers-license-format/
# https://github.com/adambullmer/USDLRegex/blob/master/regex.json

dlfile = File.read "dl_regex.json"
@dlpatterns = JSON.parse(dlfile)
# End Drivers License check

# Antipattern import
# antipatternregex.json
apfile = File.read "antipatternregex.json"
@apatterns = JSON.parse(apfile)

# Exit if no args
if ARGV.empty?
    puts "Usage: ruby " + $0 + " /path/to/search/\n\n"  
    exit
end

# Spinner
spinner = Enumerator.new do |e|
  loop do
    e.yield '|'
    e.yield '/'
    e.yield '-'
    e.yield '\\'
  end
end

# Define path
path = ARGV[0].dup
path = path << '/' unless path.end_with?('/')

# FileMagic
fm = FileMagic.new 

# File Log
filelog = open("pii-file.log","a")
fcount = 0
fskip = 0
fcheck = 0
fpatternmatch = 0
fantipatternmatch = 0
# Find all files
Dir.glob(path + "**/*").each do |file|
    $file = file
    # Skip directories
    next unless File.file?(file)
    fcount += 1
    
    # Find mimetype
    mimetype = fm.file(file)
    
    # Spin the spinner
    #spin = "\r" + spinner.next + " Checking: " + file[1...68]
    #print spin.ljust(80)
    
    # Read files based on type and find PII
    if mimetype =~ /ascii|utf-8|plain/i
        fcheck += 1
        logentry = "[Info] File: " + file + "\n"
        filelog.write(logentry)
        findpii(File.open(file),file)
    elsif
        mimetype =~ /Microsoft OOXML|Composite Document File V2 Document|PDF document/
        yomu = Yomu.new file
        text = yomu.text 
        logentry = "[Info] File: " + file + "\n"
        filelog.write(logentry)
        fcheck += 1
        findpii(text,file)
    end
end
puts "Files Counted: " + fcount.to_s + "\n"
puts "Files Checked: " + fcheck.to_s + "\n"
puts "Files Skipped: " + (fcount - fcheck).to_s + "\n"
puts "Files Initially Matched: " + fpatternmatch.to_s + "\n"
puts "Files Matched after Antipatterns: " + fantipatternmatch.to_s + "\n"
puts "\r".ljust(80)
filelog.close
