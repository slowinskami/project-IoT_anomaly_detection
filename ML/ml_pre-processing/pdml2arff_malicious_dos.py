#!/usr/bin/python
# change the path (above) to reflect where you have python installed
#
# this script will take a tshark generated pdml file and turn it
# into an arff formatted file, suitable for ingestment by weka
# here's how to create the pdml file from pcap:
# tshark -T pdml -r <infile> > <outfile>
# (adding -V gets you no more data)
# usage of this script: pdml2arff.py <outfile> (outfile is pdml from above)
# ./pdml2arff.py <input_file> -o <output_file(optional)> -n (convert all strings to numerics

import csv
import time
#import progressbar
import fileinput
from datetime import datetime

#bar = progressbar.ProgressBar(widgets=[
#    ' [', progressbar.Timer(), '] ',
#    progressbar.Bar(),
#    ' (', progressbar.ETA(), ') ',
#])

class myDialect(csv.Dialect):
    delimiter = ','
    quotechar = '"'
    quoting = csv.QUOTE_NONNUMERIC
    lineterminator = "\n"
    doublequote = False
    skipinitialspace = False

#
# Define a simple class to wrap functions
#
class PdmlConvert:
    def __init__( self, templateString , numbers_only=False ):
        self.template = templateString
        self.numbers_only = numbers_only
        self.headers = [
            "packet_id",
            "num",
            "len",
            "caplen",
            "timestamp",
            "frame.encap_type",
            "frame.offset_shift",
            "frame.time_epoch",
            "frame.time_delta",
            "frame.time_delta_displayed",
            "frame.time_relative",
            "frame.number",
            "frame.len",
            "frame.cap_len",
            "frame.marked",
            "frame.ignored",
            "eth.lg",#new added
            "eth.ig",#new added
            #"eth.type",#new added
            "eth.src", #NEW ADDED!!!!
            "eth.dst",  #NEW ADDED!!!!!
            "ip.version",
            "ip.hdr_len",
            "ip.dsfield.dscp",
            "ip.dsfield.ecn",
            "ip.src",
            "ip.dst",
            "ip.len",
            "ip.flags",
            "ip.flags.rb",
            "ip.flags.df",
            "ip.flags.mf",
            "ip.frag_offset",
            "ip.ttl",
            "ip.proto",
            "ip.checksum.status",
            "tcp.srcport",
            "tcp.dstport",
            "tcp.stream",
            "tcp.len",
            "tcp.seq",
            "tcp.nxtseq",
            "tcp.ack",
            "tcp.hdr_len",
            # "tcp.flags",
            "tcp.flags.res",
            "tcp.flags.ns",
            "tcp.flags.cwr",
            "tcp.flags.ecn",
            "tcp.flags.urg",
            "tcp.flags.ack",
            "tcp.flags.push",
            "tcp.flags.reset",
            "tcp.flags.syn",
            "tcp.flags.fin",
            "tcp.window_size_value",
            "tcp.window_size",
            "tcp.window_size_scalefactor",
            "tcp.checksum.status",
            "tcp.urgent_pointer",
            "tcp.options.nop",#new added
            "tcp.options.timestamp.tsval",
            "tcp.options.timestamp.tsecr",
            "tcp.options.mss_val",#new added
            "tcp.options.sack_perm",#new added
            # "tcp.analysis.ack_rtt",#new added NOT INT
            # "tcp.analysis.initial_rtt",#new added NOT INT
            "tcp.analysis.bytes_in_flight",
            "tcp.analysis.push_bytes_sent",
            "tcp.time_relative",
            "tcp.time_delta",
            "tcp.payload",
            "icmp.type",
            "icmp.code",
            "icmp.ident",
            "icmp.checksum.status",#new added
            "icmp.seq",
            "icmp.seq_le",
            "icmp.resp_in",
            "icmp.resp_to",#new added
            #"icmp.resptime",
            "data.len",
            "ssl.record.content_type",#new added
            "ssl.record.version",#new added
            "ssl.record.length",#new added
            "arp.hw.type",#new added
            "arp.proto.type",#new added
            "arp.hw.size",#new added
            "arp.proto.size",#new added
            "arp.opcode",#new added
            # "http.request.method",#new added
            "http.response.code",#new added
            "http.content_length",#new added
            "http.response",#new added
            "http.response_number",#new added
            "http.request",#new added
            "http.request_number",#new added
            "classicstun.type", #new added
            "classicstun.length", #new added
            "udp.srcport",
            "udp.dstport",
            "udp.length",
            "udp.checksum.status",
            "udp.stream",
            "dns.flags.response",
            "dns.flags.opcode",
            "dns.flags.truncated",
            "dns.flags.recdesired",
            "dns.flags.z",
            "dns.flags.checkdisable",
            "dns.flags.rcode",#new added
            "dns.count.queries",
            "dns.count.answers",
            "dns.count.auth_rr",
            "dns.qry.name.len",#new added
            "dns.count.labels",#new added
            "dns.resp.type",#new added
            "dns.resp.class",#new added
            "dns.resp.ttl",#new added
            "dns.resp.len",#new added
            "igmp.version",#new added
            "igmp.type",
            "igmp.max_resp",
            "igmp.checksum.status",#new added
            "ntp.flags.li",
            "ntp.flags.vn",
            "ntp.flags.mode",
            "ntp.stratum",
            "ntp.ppoll",
            "ntp.rootdelay",
            "ntp.rootdispersion",
            "ntp.precision",
            "bootp.type",#new added
            "bootp.hw.type",#new added
            "bootp.hw.len",#new added
            "bootp.hops",#new added
            "bootp.secs",#new added
            "bootp.flags.bc",#new added
            "bootp.flags.reserved",#new added
            "bootp.dhcp"#new added
        ]
        self.results = []
        self.packet_count = 1

    #
    # convert the given input to ARFF format
    #
    def convert_file( self, input_file , **kwargs ):
        fname,ext = self.parse_filename( input_file )
        output_file = kwargs.get( 'output_file', fname+'-mal_iot-toolkit.arff' )
        startTime = datetime.now()
        print(output_file + ' is about to be generated...')
        self.parse_file( input_file )
        print('finished parsing file...') #medebugging
        print('building header...') #medebugging
        header = self.build_header( input_file )    # build the top section of output file
        print('writing header') #medebugging
        self.write_to_file( header , output_file )    # write top section to output file
        print('writing data') #medebugging
        self.append_array_of_dict_to_csv( output_file )    # write data to output file
        print('finished writing data') #medebugging
        self.remove_quotation_marks_from_question_marks( output_file ) # remove all quotation marks around question marks
        print('removed quotation marks') #medebugging
        print(output_file + ' has been generated successfully in ' + str(datetime.now() - startTime) + '...')

    #
    # Replaces all instances of '"?"' with '?' in the file output_file
    # Saves back to output_file
    #
    def remove_quotation_marks_from_question_marks ( self, output_file ):
        # Read in the file
        with open(output_file, 'r') as file :
          filedata = file.read()

        # Replace the target string
        filedata = filedata.replace('"?"', '?')

        # Write the file out again
        with open(output_file, 'w') as file:
          file.write(filedata)

    #
    #  uses xml.dom.minidom to parse input xml file
    #  - reads each packet -> proto -> field
    #  - creates a key/value results dict {} for each field
    #  - new fields are added to headers array
    #
    def parse_file( self , file ):
        counter = 0
        print('in parsefile...') #medebugging
        from xml.dom import minidom    # load minidom
        print('imported the minidom...') #medebugging
        self.clean_file( file )        # found a parsing error in input data, see clean_file for info
        print('cleaned the file...') #medebugging
        xmldoc = minidom.parse( file )    # use minidom to parse xml
        print('parsed the xml with the minidom...') #medebugging
        packetCount = len(xmldoc.getElementsByTagName('packet'))
        print('starting the parsing...') #medebugging
        for packet in xmldoc.getElementsByTagName('packet'):# for every packet -> proto -> field...
            counter +=1
#            bar.update((counter/packetCount)*100)
            print(counter) #medebugging
            self.parse_packet(packet)

    #
    #
    def parse_packet( self , packet ):
        id = self.packet_count
        self.packet_count += 1
        arf = self.create_arf( id )
        for field in packet.getElementsByTagName('field'):
            if field.getAttribute('name') in self.headers:
                arf = self.parse_field_into_arf( arf , field )
            for subfield in field.getElementsByTagName('field'):
                arf = self.parse_field_into_arf( arf , subfield )
        self.results.append( arf )


    #
    # parse_field_into_arf ( arf , field )
    #                      Adds any field or subfields to arf {} if it has a value
    #
    def parse_field_into_arf( self , arf , field ):
        field_name = field.getAttribute('name')    # get name attribute of field
        arf = self.append_key_value( field_name , self.get_value_from_field( field ) , arf )    # append key/val to arf dict {}

        # Some fields have children subfields with values
        for subfield in field.getElementsByTagName('field'):
            sf_name = subfield.getAttribute('name')
            arf = self.append_key_value( sf_name , self.get_value_from_field( subfield ) , arf )
        return arf

    #
    #
    #!!!!!!!!! CHANGE HERE FOR ETH and IP ADDR exclusion
    def append_key_value( self , key , value , map ):
        if value == '':
            return map
        if not key in self.headers and key != 'ip.src' and key != 'ip.dst' and key != 'eth.src' and key != 'eth.dst':
            self.headers.append(key)
        map[key] = value
        return map

    #
    # Returns an unmaskedvalue or a vlue or '' from field attributes
    #
    def get_value_from_field( self , field ):
        # -------------------------------------        
        # GENINFO Layer
        try:
            if field.getAttribute('name') == "num":
                return int(field.getAttribute('size'))
            elif field.getAttribute('name') == "len":
                return float(field.getAttribute('show'))
            elif field.getAttribute('name') == "caplen":
                return float(field.getAttribute('show'))
            elif field.getAttribute('name') == "timestamp":
                return float(field.getAttribute('value'))

            # -------------------------------------
            # Frame Layer
            elif field.getAttribute('name') == "frame.encap_type":
                return float(field.getAttribute('show'))   
            elif field.getAttribute('name') == "frame.offset_shift":
                return float(field.getAttribute('show'))
            elif field.getAttribute('name') == "frame.time_epoch":
                return float(field.getAttribute('show'))
            elif field.getAttribute('name') == "frame.time_delta":
                return float(field.getAttribute('show'))
            elif field.getAttribute('name') == "frame.time_delta_displayed":
                return float(field.getAttribute('show'))
            elif field.getAttribute('name') == "frame.time_relative":
                return float(field.getAttribute('show'))
            elif field.getAttribute('name') == "frame.number":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "frame.len":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "frame.cap_len":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "frame.marked":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "frame.ignored":
                return int(field.getAttribute('show'))
                # this attribute is a string
            # elif field.getAttribute('name') == "frame.protocols":
            #     return str(field.getAttribute('show'))

            # -------------------------------------
            # Ethernet Protocol
            #Excluded dst, dst resolved, addr, addr resolved, source and source resolved because of identifiable information
            elif field.getAttribute('name') == "eth.lg":#new added SHOULD BE CATEGORICAL - 0,1
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "eth.ig":#new added SHOULD BE CATEGORICAL - 0,1
                return int(field.getAttribute('show'))
            #elif field.getAttribute('name') == "eth.type":#new added
            #    return int(field.getAttribute('show')) #STRING/(hex) NEEDS MAPPING (if/else)
            elif field.getAttribute('name') == "eth.src":
                return field.getAttribute('show')
            elif field.getAttribute('name') == "eth.dst":
                return field.getAttribute('show')
            # --------------------------------------
            # IP Layer
            elif field.getAttribute('name') == "ip.version":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "ip.hdr_len":
                return int(field.getAttribute('show'))
            # elif field.getAttribute('name') == "ip.dsfield":
            #     return int(field.getAttribute('value'))
            elif field.getAttribute('name') == "ip.dsfield.dscp":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "ip.hdr_len":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "ip.dsfield.ecn":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "ip.src":
                return field.getAttribute('show')
            elif field.getAttribute('name') == "ip.dst":
                return field.getAttribute('show')
            elif field.getAttribute('name') == "ip.len":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "ip.flags":#this should not be the value =40 but rather the show BUT show is in HEX (value is not relevant) POTENTIAL REMOVAL OR CONVERT?
                return int(field.getAttribute('value'))
            elif field.getAttribute('name') == "ip.flags.rb":
                return int(field.getAttribute('show')) #show not value
            elif field.getAttribute('name') == "ip.flags.df":
                return int(field.getAttribute('show')) #show not value
            elif field.getAttribute('name') == "ip.flags.mf":
                return int(field.getAttribute('show')) #show not value
            elif field.getAttribute('name') == "ip.frag_offset":
                return int(field.getAttribute('show')) #show not value
            elif field.getAttribute('name') == "ip.ttl":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "ip.proto":
                return int(field.getAttribute('show'))
            # elif field.getAttribute('name') == "ip.checksum":
            #     return int(field.getAttribute('value')) #DO NOT INCLUDE BECAUSE WE DON'T WANT IT TO DEPEND ON THE PAYLOAD?
            elif field.getAttribute('name') == "ip.checksum.status":
                return int(field.getAttribute('show'))


            # --------------------------------------
            # TCP Layer
            elif field.getAttribute('name') == "tcp.srcport":#new selected
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "tcp.dstport":#new selected
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "tcp.stream":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "tcp.len":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "tcp.seq":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "tcp.nxtseq":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "tcp.ack":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "tcp.hdr_len":
                return int(field.getAttribute('show'))
            # elif field.getAttribute('name') == "tcp.flags": #NOT PARSING C2!!
            #     return int(field.getAttribute('value'))
            elif field.getAttribute('name') == "tcp.flags.res":
                return int(field.getAttribute('value'))
            elif field.getAttribute('name') == "tcp.flags.ns":
                return int(field.getAttribute('value'))
            elif field.getAttribute('name') == "tcp.flags.cwr":
                return int(field.getAttribute('value'))
            elif field.getAttribute('name') == "tcp.flags.ecn":
                return int(field.getAttribute('value'))
            elif field.getAttribute('name') == "tcp.flags.urg":
                return int(field.getAttribute('value'))
            elif field.getAttribute('name') == "tcp.flags.ack":
                return int(field.getAttribute('value'))
            elif field.getAttribute('name') == "tcp.flags.push":
                return int(field.getAttribute('value'))
            elif field.getAttribute('name') == "tcp.flags.reset":
                return int(field.getAttribute('value'))
            elif field.getAttribute('name') == "tcp.flags.syn":
                return int(field.getAttribute('value'))
            elif field.getAttribute('name') == "tcp.flags.fin":
                return int(field.getAttribute('value'))
                # tcp.flags.str is a string attribute which just simply lists all the flags
            # elif field.getAttribute('name') == "tcp.flags.str":
            #     return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "tcp.window_size_value":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "tcp.window_size":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "tcp.window_size_scalefactor":
                return int(field.getAttribute('show'))
                # tcp.checksum is supposed to be a string
            # elif field.getAttribute('name') == "tcp.checksum":
            #     return int(field.getAttribute('value'))
            elif field.getAttribute('name') == "tcp.checksum.status":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "tcp.urgent_pointer":
                return int(field.getAttribute('value'))
            elif field.getAttribute('name') == "tcp.options.nop": #new added ???
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "tcp.options.timestamp.tsval":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "tcp.options.timestamp.tsecr":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "tcp.options.mss_val":#new added
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "tcp.options.sack_perm":#new added
                return int(field.getAttribute('value'))
            # elif field.getAttribute('name') == "tcp.analysis.ack_rtt":#new added NOT INT
            #     return int(field.getAttribute('value'))
            # elif field.getAttribute('name') == "tcp.analysis.initial_rtt":#new added NOT INT
            #     return int(field.getAttribute('value'))
            elif field.getAttribute('name') == "tcp.analysis.bytes_in_flight":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "tcp.analysis.push_bytes_sent":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "tcp.time_relative":
                return float(field.getAttribute('show'))
            elif field.getAttribute('name') == "tcp.time_delta":
                return float(field.getAttribute('show'))
            elif field.getAttribute('name') == "tcp.payload":#only size of the payload, not the actual payload
                return float(field.getAttribute('size'))

            # --------------------------------------
            # ICMP Layer
            elif field.getAttribute('name') == "icmp.type":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "icmp.code":#should be show not value - changed
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "icmp.ident":#should be two separate ones - BE and LE big endian and little endian... FOR sequence both BE and LE were extracted but for ident just one 
                return int(field.getAttribute('show'))
            # elif field.getAttribute('name') == "icmp.checksum": # icmp checksum is a hex value
            #     return float(field.getAttribute('show'))
            elif field.getAttribute('name') == "icmp.checksum.status":#new added, should be 1 or 2
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "icmp.seq":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "icmp.seq_le":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "icmp.resp_in":#shows all requests - NaN in Weka though (??) check for bigger data sample as this sample might just simply not include this
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "icmp.resp_to":#new added - shows all responses - works ok - was resp_in no resp_to, added 
                return int(field.getAttribute('show'))
            #elif field.getAttribute('name') == "icmp.resptime":#new added 
            #    return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "data.len":
                return int(field.getAttribute('show'))

            # --------------------------------------
            # SSL Layer
            elif field.getAttribute('name') == "ssl.record.content_type":#application data or something else
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "ssl.record.version":#application data or something else STARTS WITH 0 - might be problematic?
                return int(field.getAttribute('value'))
            elif field.getAttribute('name') == "ssl.record.length":
                return int(field.getAttribute('show'))

            # --------------------------------------
            # ARP Layer
            elif field.getAttribute('name') == "arp.hw.type":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "arp.proto.type":#starts with 0 might be problematic + duplication of ip.ver?
                return int(field.getAttribute('value'))
            elif field.getAttribute('name') == "arp.hw.size":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "arp.proto.size":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "arp.opcode":
                return int(field.getAttribute('show'))

            # --------------------------------------
            # HTTP Layer
            # elif field.getAttribute('name') == "http.request.method":#needs mapping as it's in STRING (POST etc CATEGORICAL)
            #     return int(field.getAttribute('show'))
            # elif field.getAttribute('name') == "http.":
            #     return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "http.response.code":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "http.content_length":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "http.response":#1 or 0 true/false
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "http.response_number":#1 or 0 true/false
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "http.request":#1 or 0 true/false
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "http.request_number":#1 or 0 true/false
                return int(field.getAttribute('show'))




            # --------------------------------------
            # UDP Layer
            elif field.getAttribute('name') == "udp.srcport":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "udp.dstport":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "udp.length":
                return int(field.getAttribute('show'))
            # elif field.getAttribute('name') == "udp.checksum":
            #     return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "udp.checksum.status":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "udp.stream":
                return int(field.getAttribute('show'))


            # --------------------------------------
            # Classicstun Layer - added
            elif field.getAttribute('name') == "classicstun.type":#see if not hex
                return int(field.getAttribute('value'))
            #THE ones below not really because there are usually many attributes within a one classic stun, hard to acquire all easily
            # elif field.getAttribute('name') == "classicstun.att.change.ip":#see if not hex
            #     return int(field.getAttribute('show'))
            # elif field.getAttribute('name') == "classicstun.att.change.port":#see if not hex
                # return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "classicstun.length":#see if not hex
                return int(field.getAttribute('value'))





            # --------------------------------------
            # DNS Layer
            # elif field.getAttribute('name') == "dns.id":
            #     return int(field.getAttribute('value'))
            elif field.getAttribute('name') == "dns.flags.response":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "dns.flags.opcode":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "dns.flags.truncated":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "dns.flags.recdesired":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "dns.flags.z":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "dns.flags.checkdisable":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "dns.flags.rcode":#new added
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "dns.count.queries":
                return int(field.getAttribute('show'))#show not value
            elif field.getAttribute('name') == "dns.count.answers":
                return int(field.getAttribute('show'))#show not value
            elif field.getAttribute('name') == "dns.count.auth_rr":
                return int(field.getAttribute('show'))#show not value
            elif field.getAttribute('name') == "dns.qry.name.len":#new added
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "dns.count.labels":#new added
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "dns.resp.type":#new added
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "dns.resp.class":#new added
                return int(field.getAttribute('value'))
            elif field.getAttribute('name') == "dns.resp.ttl":#new added
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "dns.resp.len":#new added
                return int(field.getAttribute('show'))



            # --------------------------------------
            # IGMP Layer
            elif field.getAttribute('name') == "igmp.version":#new added
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "igmp.type":
                return int(field.getAttribute('value'))
            elif field.getAttribute('name') == "igmp.max_resp":
                return int(field.getAttribute('value'))
            elif field.getAttribute('name') == "igmp.checksum.status":#new added
                return int(field.getAttribute('show'))



            # --------------------------------------
            # NTP Layer
            elif field.getAttribute('name') == "ntp.flags.li":
                return int(field.getAttribute('value'))
            elif field.getAttribute('name') == "ntp.flags.vn":
                return int(field.getAttribute('value'))
            elif field.getAttribute('name') == "ntp.flags.mode":
                return int(field.getAttribute('value'))
            elif field.getAttribute('name') == "ntp.stratum":
                return int(field.getAttribute('value'))
            elif field.getAttribute('name') == "ntp.ppoll":
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "ntp.rootdelay":
                return float(field.getAttribute('show'))
            elif field.getAttribute('name') == "ntp.rootdispersion":
                return float(field.getAttribute('show'))
            elif field.getAttribute('name') == "ntp.precision":
                return int(field.getAttribute('show'))
            


            # --------------------------------------
            # BOOTP Layer
            elif field.getAttribute('name') == "bootp.type":#new added
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "bootp.hw.type":#new added, potential duplication
                return int(field.getAttribute('value'))
            elif field.getAttribute('name') == "bootp.hw.len":#new added
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "bootp.hops":#new added
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "bootp.secs":#new added
                return int(field.getAttribute('show'))
            elif field.getAttribute('name') == "bootp.flags.bc":#new added
                return int(field.getAttribute('value'))
            elif field.getAttribute('name') == "bootp.flags.reserved":#new added
                return int(field.getAttribute('value'))
            elif field.getAttribute('name') == "bootp.dhcp":#new added
                return int(field.getAttribute('show'))
            else:
                return ''
        except:
            print ('error - not an int base 10')
            return ''

    #
    #
    #
    def create_arf( self , id ):
        return { 'packet_id': id }

    #
    # This clean file is a simple xml cleaner of the <proto> </proto> element
    # In the input files I've seen, there is an extra </proto> which shows up
    # just before a '</packet>' in the data (often but not always).  So this function
    # counts each opening '<proto' and closing '</proto>' and whenever we see an extra
    # (count < 0) we do not output that extra one.  This seems to clean the file properly.
    #
    def clean_file( self , file ):
        import re
        stack = 0
        output = []
        for line in open( file , 'r'):
            if re.search('<proto',line):
                stack += 1
            elif re.search('</proto>',line):
                stack -= 1

            if stack >= 0:
                output.append(line)
            else:
                stack += 1

        o = open(file,'wb')
        for line in output:
            o.write( line )

    #
    # Appends and Array of Dictionaries to given filename
    # - inserts headers at beginning (of where appending happens)
    #
    def append_array_of_dict_to_csv( self , filename ):
        csvfile = open(filename, 'ab')    # open file for appending
        dialect = myDialect()
        self.headers.append('packet_type')
        self.headers.append('class_device_type')
        self.headers.append('class_is_malicious')
        self.headers.append('class_attack_type')
        csvw = csv.DictWriter( csvfile , self.headers, '?' , dialect=dialect )    # instantiate DictWriter
        for kvs in self.results:    # for every dict result, append dict to csv
            
            # default values
            kvs['packet_type'] = '?'
            kvs['class_is_malicious'] = '0'
            kvs['class_attack_type'] = 'N/A'
            kvs['class_device_type'] = 'unknown'

            if self.numbers_only:
                kvs = self.map2num( kvs )

            # source and destination (malicious)
            if 'eth.src' in kvs and 'eth.dst' in kvs:
                if kvs['eth.dst'] == '60:e3:27:25:a1:8d':
                    kvs['class_device_type'] = 'TPLinkCam'
                    kvs['packet_type'] = 'in'
                    if kvs['eth.src'] == '44:85:00:c6:65:dd':#attacker's mac
                        kvs['class_is_malicious'] = '1'
                        kvs['class_attack_type'] = 'DoS'
                elif kvs['eth.dst'] == '50:c7:bf:66:99:2e':
                    kvs['class_device_type'] = 'TPLinkPlug'
                    kvs['packet_type'] = 'in'
                    if kvs['eth.src'] == '44:85:00:c6:65:dd':#attacker's mac
                        kvs['class_is_malicious'] = '1'
                        kvs['class_attack_type'] = 'DoS'
                elif kvs['eth.dst'] == '68:37:e9:66:a1:1e':
                    kvs['class_device_type'] = 'AmazonEcho'
                    kvs['packet_type'] = 'in'
                    if kvs['eth.src'] == '44:85:00:c6:65:dd':#attacker's mac
                        kvs['class_is_malicious'] = '1'
                        kvs['class_attack_type'] = 'DoS'
                elif kvs['eth.dst'] == 'c0:56:27:54:81:41':
                    kvs['class_device_type'] = 'BelkinCam'
                    kvs['packet_type'] = 'in'
                    if kvs['eth.src'] == '44:85:00:c6:65:dd':#attacker's mac
                        kvs['class_is_malicious'] = '1'
                        kvs['class_attack_type'] = 'DoS'
                elif kvs['eth.dst'] == '00:1c:2b:0a:e3:de':
                    kvs['class_device_type'] = 'Hive'
                    kvs['packet_type'] = 'in'
                    if kvs['eth.src'] == '44:85:00:c6:65:dd':#attacker's mac
                        kvs['class_is_malicious'] = '1'
                        kvs['class_attack_type'] = 'DoS'
                elif kvs['eth.dst'] == 'd0:52:a8:91:0a:0a':
                    kvs['class_device_type'] = 'SmartThings'
                    kvs['packet_type'] = 'in'
                    if kvs['eth.src'] == '44:85:00:c6:65:dd':#attacker's mac
                        kvs['class_is_malicious'] = '1'
                        kvs['class_attack_type'] = 'DoS'
                elif kvs['eth.dst'] == 'd0:73:d5:21:82:61':
                    kvs['class_device_type'] = 'Lifx'
                    kvs['packet_type'] = 'in'
                    if kvs['eth.src'] == '44:85:00:c6:65:dd':#attacker's mac
                        kvs['class_is_malicious'] = '1'
                        kvs['class_attack_type'] = 'DoS'
                elif kvs['eth.dst'] == 'f0:9f:c2:73:28:98':
                    kvs['class_device_type'] = 'AP'
                    kvs['packet_type'] = 'in'
                    if kvs['eth.src'] == '44:85:00:c6:65:dd':#attacker's mac
                        kvs['class_is_malicious'] = '1'
                        kvs['class_attack_type'] = 'DoS'
                elif kvs['eth.dst'] == '84:2b:2b:72:d7:f8':
                    kvs['class_device_type'] = 'Firewall'
                    kvs['packet_type'] = 'in'
                    if kvs['eth.src'] == '44:85:00:c6:65:dd':#attacker's mac
                        kvs['class_is_malicious'] = '1'
                        kvs['class_attack_type'] = 'DoS'



            # source
            if 'eth.src' in kvs:
                if kvs['eth.src'] == '68:37:e9:66:a1:1e':
                    kvs['class_device_type'] = 'AmazonEcho'
                    kvs['packet_type'] = 'out'
                elif kvs['eth.src'] == 'c0:56:27:54:81:41':
                    kvs['class_device_type'] = 'BelkinCam'
                    kvs['packet_type'] = 'out'
                elif kvs['eth.src'] == '00:1c:2b:0a:e3:de':
                    kvs['class_device_type'] = 'Hive'
                    kvs['packet_type'] = 'out'
                elif kvs['eth.src'] == 'd0:52:a8:91:0a:0a':
                    kvs['class_device_type'] = 'SmartThings'
                    kvs['packet_type'] = 'out'
                elif kvs['eth.src'] == 'd0:73:d5:21:82:61':
                    kvs['class_device_type'] = 'Lifx'
                    kvs['packet_type'] = 'out'
                elif kvs['eth.src'] == '60:e3:27:25:a1:8d':
                    kvs['class_device_type'] = 'TPLinkCam'
                    kvs['packet_type'] = 'out'
                elif kvs['eth.src'] == '50:c7:bf:66:99:2e':
                    kvs['class_device_type'] = 'TPLinkPlug'
                    kvs['packet_type'] = 'out'
                elif kvs['eth.src'] == 'f0:9f:c2:73:28:98':
                    kvs['class_device_type'] = 'AP'
                    kvs['packet_type'] = 'out'
                elif kvs['eth.src'] == '84:2b:2b:72:d7:f8':
                    kvs['class_device_type'] = 'Firewall'
                    kvs['packet_type'] = 'out'



                

            # remove these as we do not want them to appear in our results
            if 'ip.src' in kvs:
                kvs.pop('ip.src', None)
            if 'ip.dst' in kvs:
                kvs.pop('ip.dst', None)
            if 'eth.src' in kvs:
                kvs.pop('eth.src', None)
            if 'eth.dst' in kvs:
                kvs.pop('eth.dst', None)


            csvw.writerow( kvs )

    #
    # Writes text to filename
    #
    def write_to_file( self , text , filename ):
        f = open( filename , 'wb')
        f.write( text )

    #
    # Build header/top section of output file
    #

    #Initially discussed version of the header. Categorised the features listed in the if statements below. 
    #Need to: - see bigger data sample for "testbed" values for: ip.proto, igmp.type, udp.srcport, udp.dstport, tcp.srcport, tcp.dstport, ip.checksum.status, icmp.type, icmp.code (?), udp.checksum.status, tcp.checksum.status
    #ALSO fix the dsfield.dscp and dsfield.ecn or just the dsfield wrapper field
    def build_header( self , filename ):
        from string import Template
        text = Template( self.template ) # Template example:
        attr_str = "" # temp = Template('this is a $INSERT')
        for attr in self.headers:     # print temp.substitute(INSERT='test')
            if attr == "ip.version":
                attr_str += "@attribute " + attr + " {4, 6}" + "\n" 
            elif attr == "ip.flags.rb":
                attr_str += "@attribute " + attr + " {0, 1}" + "\n" 
            elif attr == "ip.flags.df":
                attr_str += "@attribute " + attr + " {0, 1}" + "\n" 
            elif attr == "ip.flags.mf":
                attr_str += "@attribute " + attr + " {0, 1}" + "\n" 
            # elif attr == "ip.proto":
            #     attr_str += "@attribute " + attr + " {1, 6, 17, 2}" + "\n" #SHOULD BE MUCH MUCH MORE https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers BUT OUR DATA SHOWS JUST THESE ONES
            #elif attr == "ip.checksum.status": 
                #attr_str += "@attribute " + attr + " {2}" + "\n" # ONLY value 2 - check on a bigger sample
            elif attr == "tcp.flags.res":
                attr_str += "@attribute " + attr + " {0, 1}" + "\n" 
            elif attr == "tcp.flags.ns":
                attr_str += "@attribute " + attr + " {0, 1}" + "\n" 
            elif attr == "tcp.flags.cwr":
                attr_str += "@attribute " + attr + " {0, 1}" + "\n" 
            elif attr == "tcp.flags.ecn":
                attr_str += "@attribute " + attr + " {0, 1}" + "\n" 
            elif attr == "tcp.flags.urg":
                attr_str += "@attribute " + attr + " {0, 1}" + "\n" 
            elif attr == "tcp.flags.ack":
                attr_str += "@attribute " + attr + " {0, 1}" + "\n" 
            elif attr == "tcp.flags.push":
                attr_str += "@attribute " + attr + " {0, 1}" + "\n" 
            elif attr == "tcp.flags.reset":
                attr_str += "@attribute " + attr + " {0, 1}" + "\n" 
            elif attr == "tcp.flags.syn":
                attr_str += "@attribute " + attr + " {0, 1}" + "\n" 
            elif attr == "tcp.flags.fin":
                attr_str += "@attribute " + attr + " {0, 1}" + "\n" 

            #elif attr == "tcp.checksum.status": 
                #attr_str += "@attribute " + attr + " {2}" + "\n" # use this for "nominal" data type WHY ONLY 2 ??????
            #elif attr == "icmp.type":
                #attr_str += "@attribute " + attr + " {}" + "\n" # use this for "nominal" data type PROBLEMATIC - theoretically fields 0-255 BUT could create bins for codes 20-29, 44-252 https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml CHECK ON BIGGER SAMPLE
            #elif attr == "icmp.code":
                #attr_str += "@attribute " + attr + " {}" + "\n" # use this for "nominal" data type PROBLEMATIC .... different codes for different types - might confuse the classifier
            # elif attr == "http.request.method":
                # attr_str += "@attribute " + attr + " {PUT, POST, GET, HEAD, DELETE, CONNECT, OPTIONS, TRACE, PATCH }" + "\n" 
            #elif attr == "udp.srcport": 
                #attr_str += "@attribute " + attr + " {}" + "\n" # sometimes randomised? list most popular ones and mark the rest as "Others" 
            #elif attr == "udp.dstcport": 
                #attr_str += "@attribute " + attr + " {}" + "\n" # sometimes randomised? list most popular ones and mark the rest as "Others" BINNING (TRY!!)
            #elif attr == "udp.checksum.status": 
                #attr_str += "@attribute " + attr + " {2,3}" + "\n" # use this for "nominal" data type WHY ONLY 2 ?????? AND 3???
            
            elif attr == "dns.flags.response":
                attr_str += "@attribute " + attr + " {0, 1}" + "\n" 
            elif attr == "dns.flags.opcode":
                attr_str += "@attribute " + attr + " {0, 1}" + "\n" 
            elif attr == "dns.flags.truncated":
                attr_str += "@attribute " + attr + " {0, 1}" + "\n" 
            elif attr == "dns.flags.recdesired":
                attr_str += "@attribute " + attr + " {0, 1}" + "\n" 
            elif attr == "dns.flags.z":
                attr_str += "@attribute " + attr + " {0, 1}" + "\n" 
            elif attr == "dns.flags.checkdisable":
                attr_str += "@attribute " + attr + " {0, 1}" + "\n" 
            # elif attr == "dns.flags.rcode":
            #     attr_str += "@attribute " + attr + " {0, 1}" + "\n"



            # elif attr == "ntp.flags.li":
            #     attr_str += "@attribute " + attr + " {0, 1}" + "\n" 
            # elif attr == "ntp.flags.vn":
            #     attr_str += "@attribute " + attr + " {0, 1}" + "\n" 
            # elif attr == "ntp.flags.mode":
            #     attr_str += "@attribute " + attr + " {0, 1}" + "\n" 


            # elif attr == "bootp.flags.bc":
            #     attr_str += "@attribute " + attr + " {0, 1}" + "\n" 
            # elif attr == "bootp.flags.reserved":
            #     attr_str += "@attribute " + attr + " {0, 1}" + "\n" 



            # elif attr == "igmp.type":
                # attr_str += "@attribute " + attr + " {11, 16, 0, 3, 1, 9, 4, 2}" + "\n" # these ones were chosen by autoencoder https://www.iana.org/assignments/igmp-type-numbers/igmp-type-numbers.xhtml  1-8 could be grouped together as reserved obsolete and 9-10 unassigned 
            else:
                attr_str += "@attribute " + attr + " numeric" + "\n" # use this if outputting "numeric" data type
        attr_str += "@attribute packet_type {in, out}\n"
        attr_str += "@attribute class_device_type {AmazonEcho, BelkinCam, Hive, SmartThings, Lifx, TPLinkCam, TPLinkPlug, AP, Firewall, unknown}\n"
        attr_str += "@attribute class_is_malicious {0, 1}\n"
        attr_str += "@attribute class_attack_type {DoS, mitm, scanning, iot-toolkit, deauth, N/A}\n"
        return text.substitute(RELATION=filename,ATTRIBUTES=attr_str)

    #
    # Parse a filename into its base name and extension
    # returns [basename,ext] or 'Invalid Filename'
    #
    def parse_filename( self , name ):
        import re
        r = re.search( r"(\S+)(\.\S{1,4})$", name )
        if r:
            return [ r.group(1) , r.group(2) ]
        else:
            raise 'Invalid Filename'

    #
    #  converts each value of the given map/dict to an integer using str2num
    #
    def map2num( self , m ):
        result = {}
        for k,v in m.iteritems():
            result[k] = self.str2num(v)
        return result

    #
    # Convert a string to a number (takes the ord value of each letter and
    # combines it then converts it to int)
    # i.e. str2num( 'abc' ); ord('a') = 97; "979899" => returns 979899 as int
    #
    def str2num( self , s ):
        if type(s) is int:
            return s
        num = ''
        for letter in s:
            o = ord(letter)
            num += str(o)
        return int(num)

    #
    #  Write errors to log
    #
    def error_log( self , message ):
        f = open('pdml.errors.log','wb')
        f.write( message )

# Template ARFF File
arff = '''
%
% This arff created by pdml2arff.py
% Written by Tim Stello with input from Charlie Fowler, spring 2013
% This script takes a pdml file created by tshark and converts it to arff
%
@relation $RELATION
%
%attributes
%
$ATTRIBUTES
%
@data
%
'''

#
# Main: this portion executes only when this file is executed
# from the command line.  If you 'import' this file, this section
# will not execute
#
if __name__ == '__main__':
    print('Executing main loop') #medebugging
    import sys
    usage = "./pdml2arffpy <input_file> -o <output_file (optional)> -n (convert all strings to numerics)\n"
    numbers_only = False
    if '-n' in sys.argv:
        numbers_only = True
        sys.argv.remove('-n')
    print('Calling pdmlconvert') #medebugging
    pdmlc = PdmlConvert(arff , numbers_only )
    print('Finished pdmlconvert') #medebugging
    l = len(sys.argv)
    if l == 2:
        print('executing for length 2') #medebugging
        pdmlc.convert_file( sys.argv[1] )
        print('finished executing for length 2') #medebugging
    elif l == 4:
        print('executing for length 4') #medebugging
        pdmlc.convert_file( sys.argv[1] , { 'output_file':sys.argv[3] })
        print('finished executing for length 4') #medebugging
    else:
        print(usage)
        sys.exit
