require 'packetfu'

puts "NMap scan dectector"
iface = ARGV[0] || "eth0"
include PacketFu
def ids(iface)

  incident_num = 1
  attack_type = Hash.new
  attack_type[0] = "Null Scan"
  attack_type[18] =  "TCP-Connect Scan"
  attack_type[41] = "XMAS Scan"
  #String->bytes and regex for credit cards and xss.
  xss = "<script>alert('XSS');</script>"
  xss_bin = xss.each_byte.map { |b| sprintf(" 0x%02X ",b) }.join
  visa = Regexp.new(/4\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/)
  mastercard = Regexp.new(/5\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/)
  discovercard = Regexp.new(/6011(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/)
  amex = Regexp.new(/3\d{3}(\s|-)?\d{6}(\s|-)?\d{5}/)

  capture = PacketFu::Capture.new(:start => true, :iface => iface, :promisc => true)
  #capture.show_live()
  capture.stream.each do |p|
    pkt = Packet.parse p
    if pkt.is_tcp?
      tcp_flags = pkt.tcp_flags.to_i
      if tcp_flags==41 || tcp_flags==0 || tcp_flags==18
        puts "#{incident_num}. ALERT: #{attack_type[tcp_flags]} is detected from #{pkt.ip_saddr}"
        incident_num = incident_num + 1
      else
        puts pkt.payload
      end
      #next if pkt.ip_header.ip_saddr == Utils.ifconfig(iface)[:ip_saddr]
      #packet_info = [pkt.ip_saddr, pkt.ip_daddr, pkt.size, pkt.proto.last]
      #puts "%-15s -> %-15s %-4d %s" % packet_info
    else
      pkt.payload.scan(visa)
      pkt.payload.scan(mastercard)
      pkt.payload.scan(discovercard)
      pkt.payload.scan(amex)
    end
  end
end

ids(iface)

