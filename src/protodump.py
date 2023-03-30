#!/usr/bin/env python3
#----------------------------------------------------------------------#
'''
Utility to dump buffers or files encoded using Google Protobuf.
'''
#----------------------------------------------------------------------#

import sys
import base64
import binascii

logfile = sys.stdout

#----------------------------------------------------------------------#
def bytes_to_long(byte_array):
    'Read packed binary data into a long integer.'

    value = 0
    for byte in byte_array:
        value = (value << 8) | (byte & 0xff)
  
    return value

#----------------------------------------------------------------------#
def log_string(size, string, message, indent = 0, offset= None):
    'Log data in a standard format.'

    size_str = (size > 0) and ('%5d' % size) or '-----'
    offs_str = (offset is None) and '' or ('%5d:' % offset)
    if string:
        logfile.write(f'[{offs_str}{size_str:4}] {"-" * indent}[{string}] - ({message})\n')
    else:
        logfile.write(f'[{offs_str}{size_str:4}] {"-" * indent}({message})\n')
    return

#----------------------------------------------------------------------#
def log_data(size, data, message, indent= 0, decimal= False, true_size=None, offset= None):
    'Log data in a standard format.'

    if decimal:
        data_form = '[%' + ('%dd] - ' % int(0.5 + size * 2.4082399653118491))
    else:
        data_form = '[%.' + ('%dx] - ' % (size * 2))
    if true_size is not None:
        size = true_size
    size_str = (size > 0) and ('%5d' % size) or '-----'
    offs_str = (offset is None) and '' or ('%5d:' % offset)
    logfile.write(('[%s%s] %s' + data_form + '%s\n') % (offs_str, size_str, '-' * indent, data, message))
    return

#----------------------------------------------------------------------#
def log_long(size, data, index, message, indent = 0, decimal = False, true_size=None, offset= None):
    'Log data in a standard format.'

    value = bytes_to_long(data[index:index+size])
    log_data(size, value, message, indent, decimal, true_size, offset)
    return (index + size, value)

#----------------------------------------------------------------------#
def log_info(message, indent= 0, offset= None, size= 0):
    'Log an error in a standard format.'

    size_str = (size > 0) and ('%5d' % size) or '-----'
    offs_str = (offset is None) and '' or ('%5d:' % offset)
    if message.lower().startswith('start'):
        in_str = 'v'
    elif message.lower().startswith('end'):
        in_str = '^'
    else:
        in_str = '-'
    logfile.write(f'[{offs_str}{size_str}] {in_str * indent}({message})\n')
    return


#----------------------------------------------------------------------#
def log_error(message, indent= 0, offset= None):
    'Log an error in a standard format.'

    offs_str = (offset is None) and '' or f'{offset:5d}:'
    logfile.write(f'[{offs_str}ERROR] {"-" * indent}({message})\n')
    return

#----------------------------------------------------------------------#
def read_varint(data, index = 0):
    'Read a single protobuf Varint and return its value and length.'
    value  = 0
    shift  = 0
    length = 0
    while data[index+length] & 0x80:
        value  |= (data[index+length] & 0x7f) << shift
        shift  += 7
        length += 1
    value  |= data[index+length] << shift
    length += 1
    return (value, length)

#----------------------------------------------------------------------#
def dump(data, offset= 0, length= None, indent= 0):
    'Dump data assumed to be in Google Protocol Buffer format.'

    log_info('Start of Block', indent, offset)
    
    # If the data is a string, convert it to a list of integers
    if type(data) is str:
        data = map(ord, data)
    
    # Keep track of how much data we have processed
    index = 0

    # If no length is specified, process the entire data
    if length is None:
        length = len(data)
    
    # If the length is negative, this a length-prefixed message
    elif length == -1:
        length, index = read_varint(data, index)
        log_data(index, length, 'Message', indent, offset=offset)
        processed = dump(data[index:], offset + index, length, indent + 2) 
        log_info('End of Block', indent, offset, index + processed)
        return index + processed
    try:
        # Convert the data to an ASCII string
        ascstr = (''.join(map(chr, data[:length]))).decode('ascii')
        if index == 0:
            log_string(length, ascstr, 'ASCII String', indent, offset=offset)
        else:
            log_string(length, ascstr, 'ASCII String (ignoring prior data at this level)', indent, offset=offset)
    except:
        ascstr = None
    
    # Process each field in the data
    while index < length:
        # Read the tag, which consists of a tag number and tag type
        tag, tag_len = read_varint(data, index)
        tag_type = (tag & 0x07)
        tag_id   = (tag ^ tag_type) >> 3
        tag_str  = ('%%.%dx' % (tag_len * 2)) % tag
        message  = ('Tag: [%s=%3d:%d] -> %%s') % (tag_str, tag_id, tag_type)

        # Process Varint
        if tag_type == 0:
            # Read a varint field and log it
            value, fld_len = read_varint(data, index + tag_len)
            log_data(tag_len, value, message % 'Varint', indent, true_size=tag_len + fld_len, offset=offset+index)
        
        # Process 64-bit
        elif tag_type == 1:
            # Read a 64-bit integer field and log it
            fld_len = 8
            if index + tag_len + fld_len > length:
                if ascstr is None:
                    log_error('64-bit int length longer than data - aborting', indent, index + tag_len)
                log_info('End of Block', indent, offset, length)
                return length
            log_long(fld_len, data, index+1, message % '64-bit', indent, true_size=tag_len + fld_len, offset=offset+index)
        
        # Process Length-delimited
        elif tag_type == 2:
            # Read a length-delimited field and log it
            dat_len, fld_len = read_varint(data, index + tag_len)
            if index + tag_len + fld_len + dat_len > length:
                if ascstr is None:
                    log_error('Data length longer than data - aborting', indent, offset + index + tag_len)
                log_info('End of Block', indent, offset, length)
                return length
            log_data(fld_len, dat_len, message % 'Data', indent, true_size=tag_len + fld_len, offset=offset+index)
            log_long(dat_len, data, index+tag_len + fld_len, 'Data Contents', indent + 2, offset=offset+index)

            # Try to parse the data contents as a hex string
            rawdat = data[index+tag_len+fld_len:index+tag_len+fld_len+dat_len]
            hexdat = None
            b64dat = None

            if (fld_len & 1) == 0:
                try:
                    hexdat = binascii.unhexlify(rawdat) 
                    hexstr = hexdat.decode('utf-8')
                    log_string(dat_len, hexstr, 'Data Contents (from HEX)', indent + 2, offset=offset+index)
                except:
                    pass
            
            # Try to parse the data contents as a base-64 string if not hex
            if (fld_len & 3) == 0 and hexdat is None:
                try:
                    b64dat = base64.b64decode(rawdat) 
                    try:
                        b64str = b64dat.decode('utf-8')
                        log_string(len(b64str), b64str, 'Data Contents (string from BASE64)', indent + 2, offset=offset+index)
                    except Exception as baserr:
                        log_data(len(b64dat), bytes_to_long(b64dat), 'Data Contents (HEX from BASE64)', indent + 2, true_size=dat_len, offset=offset+index)
                except:
                    pass
            
            # Try to parse the data contents as a raw string
            if hexdat is None and b64dat is None:
                try:
                    datstr = rawdat.decode('utf-8')
                    log_string(len(datstr), datstr, 'Data Contents (string)', indent + 2, offset=offset+index)
                except Exception:
                    pass
            
            # Also try to parse the data contents as a protobuf message
            processed = dump(data[index+tag_len+fld_len:], offset + index + tag_len + fld_len, dat_len, indent + 4)
            fld_len += dat_len

        # Process 32-bit
        elif tag_type == 5:
            fld_len = 4
            log_long(fld_len, data, index+1, message % '32-bit', indent, true_size=tag_len + fld_len, offset=offset+index)
        
        # There is no protobuf structure we can find at this point
        elif index == 0:
            if ascstr is None:
                log_error(message % 'Data does not appear to be protobuf message', indent, offset + index)
            log_info('End of Block', indent, offset, index)
            return length
        
        # Process unknown tag type that is probably an ASCII string
        elif ascstr is not None:
            log_error('Unknown message tag type [%d] with id [%d] - %d bytes remaining - data probably ASCII string' % (tag_type, tag_id, length - index), indent, offset + index)
            log_info('End of Block', indent, offset, index)
            return length
        
        # Process any other unknown tag type
        else:
            log_error('Unknown message tag type [%d] with id [%d] - %d bytes remaining' % (tag_type, tag_id, length - index), indent, offset + index)
            log_info('End of Block', indent, offset, index + 1)
            return index + 1
        index += tag_len + fld_len
    
    # If we get here, we have processed all the data
    log_info('End of Block', indent, offset, index)
    return index

#----------------------------------------------------------------------#
if __name__ == '__main__':
    fname = sys.argv[1]
    if len(sys.argv) > 2:
        offset = int(sys.argv[2])
    else:
        offset = 0
    if len(sys.argv) > 3:
        if sys.argv[3] == 'v':
            length = -1
        else:
            length = int(sys.argv[3])
    else:
        length = None
    with open(fname, 'rb') as infile:
        data = infile.read()
    dump(data[offset:], offset, length)
