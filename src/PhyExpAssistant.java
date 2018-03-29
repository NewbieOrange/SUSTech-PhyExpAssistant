import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PhyExpAssistant
{
    public static void main(String[] args)
    {
        List<PcapIf> alldevs = new ArrayList<>(); // Will be filled with NICs
        StringBuilder errbuf = new StringBuilder(); // For any error messages

        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.ERROR || alldevs.isEmpty())
        {
            System.err.printf("错误: 读取网络设备列表失败: %s%n", errbuf.toString());
            return;
        }

        System.out.println("已知网络设备 (无线网卡可能被显示为 'Microsoft'):\n");

        int i = 0;
        for (PcapIf device : alldevs)
        {
            String description = (device.getDescription() != null) ? device.getDescription() : "无描述信息";
            System.out.printf("#%d: %s [%s]%n", i++, device.getName(), description);
        }
        System.out.println();

        int choose = alldevs.size() == 1 ? 0 : -1;
        if (choose == -1)
        {
            System.out.print("请选择要监听的网络设备: ");
            Scanner scanner = new Scanner(System.in);
            while (choose < 0 || choose >= alldevs.size())
            {
                choose = scanner.nextInt();
            }
            scanner.close();
            System.out.println();
        }

        int snaplen = 64 * 1024;           // Capture all packets, no trucation
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
        int timeout = 10 * 1000;           // 10 seconds in millis

        PcapIf device = alldevs.get(choose);
        System.out.printf("已选择网络设备 '%s':%n%n", (device.getDescription() != null) ? device.getDescription() : device.getName());
        Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

        if (errbuf.length() > 0)
        {
            System.err.printf("打开网络设备时发生错误: %s%n", errbuf.toString());
        }

        AtomicInteger mcIndex = new AtomicInteger(), epIndex = new AtomicInteger();
        Pattern stdAnsPattern = Pattern.compile("StdAnswer&gt;(.*)&lt;/StdAnswer");
        Pattern stdResPattern = Pattern.compile("StdResult&gt;(.*?)&lt;/StdResult");

        PcapPacketHandler<String> jPacketHandler = (packet, user) -> {
            if (packet.hasHeader(Ip4.ID) && packet.hasHeader(Tcp.ID))
            {
                Ip4 ip4 = packet.getHeader(new Ip4());
                Tcp tcp = packet.getHeader(new Tcp());
                if (ip4.sourceToInt() == -1408104944 && tcp.source() == 9202)
                { // Ip == "172.18.6.16" && port == 9202
                    String payload = new String(tcp.getPayload());

                    Matcher stdAnsMatcher = stdAnsPattern.matcher(payload);
                    while (stdAnsMatcher.find())
                    {
                        System.out.printf("[选择题 (%d)] 答案: %s%n", mcIndex.incrementAndGet(), stdAnsMatcher.group(1).replace(';', ' '));
                    }

                    Matcher stdResMatcher = stdResPattern.matcher(payload);
                    while (stdResMatcher.find())
                    {
                        System.out.printf("[实验题 (%d)] 答案: %s%n", epIndex.incrementAndGet(), stdResMatcher.group(1));
                    }

                    int sum = mcIndex.intValue() + epIndex.intValue();
                    if (sum > 0 && !packet.hasHeader(Http.ID) && payload.endsWith("</s:Envelope>"))
                    { // The final http packet for the problem set.
                        pcap.close();
                        System.out.printf("%n拦截结束, 成功获取 %d 个答案%n", sum);
                        System.exit(0);
                    }
                }
            }
        };

        pcap.loop(-1, jPacketHandler, null);
        pcap.close();
    }
}
