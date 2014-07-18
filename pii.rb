# PII Search tool
# Zach Varnell

require 'yomu'
require 'ruby-filemagic'

def findpii(f)
    # Read each line of file
    f.each_line do |line|
                
        if !(match_data = line.match($cc)).nil?
            match_data = match_data.to_s #.gsub(/[^0-9A-Za-z]/, '')
            puts "\r[!] CC# found in " + $file + ": " + match_data + "\n\n" if luhnother(match_data) == true
        end
        if !(match_data = line.match($ssn)).nil?
            match_data = match_data.to_s    
            puts "\r[!] SSN found in " + $file + ": " + match_data + "\n\n"
        end
    end
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

# Exit if no args
if ARGV.empty?
    puts "Usage: ruby pii.rb /path/to/search/\n\n"  
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

# Find all files
Dir.glob(path + "**/*").each do |file|
    $file = file
    # Skip directories
    next unless File.file?(file)
    
    # Find mimetype
    mimetype = fm.file(file)
    
    # Spin the spinner
    spin = "\r" + spinner.next + " Checking: " + file[1...68]
    print spin.ljust(80)
    
    # Read files based on type and find PII
    if mimetype =~ /ascii|utf-8|plain/i
        findpii(File.open(file))
    elsif
        mimetype =~ /Microsoft OOXML|Composite Document File V2 Document|PDF document/
        yomu = Yomu.new file
        text = yomu.text 
        findpii(text)
    end
end
puts "\r".ljust(80)
