import csv
import sys
import os
import time
import matplotlib

matplotlib.use('Agg')

import matplotlib.pyplot as plt

import ns.aodv
import ns.applications
import ns.flow_monitor
import ns.core
import ns.dsdv
import ns.dsr
import ns.internet
import ns.mobility
import ns.network
import ns.olsr
import ns.wifi

__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))
__workdir__ = os.path.join(__location__, "work")


class RoutingExperiment:
    def __init__(self):
        self.bytesTotal = 0
        self.packetsReceived = 0

        self.port = 9
        self.m_CSVfileName = "manet-routing.output"
        self.m_nodes = 50
        self.m_protocolName = ""
        self.m_txp = 8.9048
        self.m_total_time = 1000
        self.m_node_speed = 20  
        self.m_debugger = True

        self.m_nSinks = 10
        self.m_protocol = 3
        self.m_node_pause = 0  

    def PrintReceivedPacket(self, socket, packet, senderAddress):
        oss = str(ns.core.Simulator.Now().GetSeconds()) + " " + str(socket.GetNode().GetId())

        if ns.network.InetSocketAddress.IsMatchingType(senderAddress):
            addr = ns.network.InetSocketAddress.ConvertFrom(senderAddress)  
            ipv4 = addr.GetIpv4()  
            oss += " received one packet from "
            sys.stdout.write(oss)
            print ipv4
        else:
            oss += " received one packet!"
            print oss

    def ReceivePacket(self, socket):
        senderAddress = ns.network.Address()  
        packet = socket.RecvFrom(senderAddress)
        while packet != None:
            self.bytesTotal += packet.GetSize()
            self.packetsReceived += 1
            self.PrintReceivedPacket(socket, packet, senderAddress)
            packet = socket.RecvFrom(senderAddress)

    def WriteHeaderCsv(self):
        with open(os.path.join(__workdir__, (self.m_CSVfileName + ".csv")), 'w') as csvfile:
            spamwriter = csv.writer(csvfile, delimiter=';',
                                    quotechar='|', quoting=csv.QUOTE_MINIMAL)
            spamwriter.writerow(
                ['SimulationSecond',
                 'ReceiveRate',
                 'PacketsReceived',
                 'PacketDeliveryRatio',
                 'NumberOfSinks',
                 'RoutingProtocol',
                 'TransmissionPower'])

    def CheckThroughput(self):
        kbs = (self.bytesTotal * 8.0) / 1000
        self.bytesTotal = 0
        now = int((ns.core.Simulator.Now()).GetSeconds())

        pdr = self.packetsReceived / (4 * self.m_nSinks)

        with open(os.path.join(__workdir__, (self.m_CSVfileName + ".csv")), 'a') as csvfile:
            spamwriter = csv.writer(csvfile, delimiter=';',
                                    quotechar='|', quoting=csv.QUOTE_MINIMAL)
            spamwriter.writerow([now, kbs, self.packetsReceived, pdr, self.m_nSinks, self.m_protocolName, self.m_txp])

        self.packetsReceived = 0
        ns.core.Simulator.Schedule(ns.core.Seconds(1.0), RoutingExperiment.CheckThroughput, self)

    def SetupPacketReceive(self, addr, node):
        tid = ns.core.TypeId.LookupByName("ns3::UdpSocketFactory")  # type: TypeId
        sink = ns.network.Socket.CreateSocket(node, tid)  # type: Ptr<Socket>
        local = ns.network.InetSocketAddress(addr, self.port)  # type: InetSocketAddress
        sink.Bind(local)
        sink.SetRecvCallback(self.ReceivePacket)

        return sink

    @staticmethod
    def print_stats(output, st):
        print >> output, "  Tx Bytes: ", st.txBytes
        print >> output, "  Rx Bytes: ", st.rxBytes
        print >> output, "  Tx Packets: ", st.txPackets
        print >> output, "  Rx Packets: ", st.rxPackets
        print >> output, "  Lost Packets: ", st.lostPackets
        if st.rxPackets > 0:
            print >> output, "  Mean{Delay}: ", (st.delaySum.GetSeconds() / st.rxPackets)
            print >> output, "  Mean{Jitter}: ", (st.jitterSum.GetSeconds() / (st.rxPackets - 1))
            print >> output, "  Mean{Hop Count}: ", float(st.timesForwarded) / st.rxPackets + 1

        if 0:
            print >> output, "Delay Histogram"
            for i in range(st.delayHistogram.GetNBins()):
                print >> output, " ", i, "(", st.delayHistogram.GetBinStart(i), "-", \
                    st.delayHistogram.GetBinEnd(i), "): ", st.delayHistogram.GetBinCount(i)
            print >> output, "Jitter Histogram"
            for i in range(st.jitterHistogram.GetNBins()):
                print >> output, " ", i, "(", st.jitterHistogram.GetBinStart(i), "-", \
                    st.jitterHistogram.GetBinEnd(i), "): ", st.jitterHistogram.GetBinCount(i)
            print >> output, "PacketSize Histogram"
            for i in range(st.packetSizeHistogram.GetNBins()):
                print >> output, " ", i, "(", st.packetSizeHistogram.GetBinStart(i), "-", \
                    st.packetSizeHistogram.GetBinEnd(i), "): ", st.packetSizeHistogram.GetBinCount(i)

        for reason, drops in enumerate(st.packetsDropped):
            print "  Packets dropped by reason %i: %i" % (reason, drops)

    def Run(self, *positional_parameters, **keyword_parameters):
        ns.network.Packet.EnablePrinting()

        if "SINKS" in os.environ:
            self.m_nSinks = int(os.environ["SINKS"])
        if "TXP" in os.environ:
            self.m_txp = float(os.environ["TXP"])
        if "TOTAL_TIME" in os.environ:
            self.m_total_time = int(os.environ["TOTAL_TIME"])
        if "NODES" in os.environ:
            self.m_nodes = int(os.environ["NODES"])
        if "PROTOCOL" in os.environ:
            self.m_protocol = int(os.environ["PROTOCOL"])
        if "NODE_SPEED" in os.environ:
            self.m_node_speed = int(os.environ["NODE_SPEED"])
        if "NODE_PAUSE" in os.environ:
            self.m_node_pause = int(os.environ["NODE_PAUSE"])
        if "FILE_NAME" in os.environ:
            self.m_CSVfileName = os.environ["FILE_NAME"]

        if 'nSinks' in keyword_parameters:
            self.m_nSinks = keyword_parameters['nSinks'];
        if 'txp' in keyword_parameters:
            self.m_txp = keyword_parameters['txp'];
        if 'TotalTime' in keyword_parameters:
            self.m_total_time = keyword_parameters['TotalTime'];
        if 'Nodes' in keyword_parameters:
            self.m_nodes = keyword_parameters['Nodes'];
        if 'Protocol' in keyword_parameters:
            self.m_protocol = keyword_parameters['Protocol'];
        if 'NodeSpeed' in keyword_parameters:
            self.m_node_speed = keyword_parameters['NodeSpeed'];
        if 'NodePause' in keyword_parameters:
            self.m_node_pause = keyword_parameters['NodePause'];
        if 'CSVfileName' in keyword_parameters:
            self.m_CSVfileName = keyword_parameters['CSVfileName'];

        self.m_CSVfileName += "." + str(time.time())
        rate = "2048bps"  
        phyMode = "DsssRate11Mbps"
        tr_name = self.m_CSVfileName + "-compare"
        self.m_protocolName = "protocol"

        ns.core.Config.SetDefault("ns3::OnOffApplication::PacketSize", ns.core.StringValue("64"))
        ns.core.Config.SetDefault("ns3::OnOffApplication::DataRate", ns.core.StringValue(rate))

        ns.core.Config.SetDefault("ns3::WifiRemoteStationManager::NonUnicastMode", ns.core.StringValue(phyMode));

        adhocNodes = ns.network.NodeContainer()
        adhocNodes.Create(self.m_nodes)

        wifi = ns.wifi.WifiHelper()
        wifi.SetStandard(ns.wifi.WIFI_PHY_STANDARD_80211b)

        wifiPhy = ns.wifi.YansWifiPhyHelper.Default()
        wifiChannel = ns.wifi.YansWifiChannelHelper()
        wifiChannel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel")
        wifiChannel.AddPropagationLoss("ns3::FriisPropagationLossModel")
        wifiPhy.SetChannel(wifiChannel.Create())

        wifiMac = ns.wifi.WifiMacHelper()
        wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                     "DataMode", ns.core.StringValue(phyMode),
                                     "ControlMode", ns.core.StringValue(phyMode))

        wifiPhy.Set("TxPowerStart", ns.core.DoubleValue(self.m_txp))
        wifiPhy.Set("TxPowerEnd", ns.core.DoubleValue(self.m_txp))

        wifiMac.SetType("ns3::AdhocWifiMac")
        adhocDevices = wifi.Install(wifiPhy, wifiMac, adhocNodes)  # type: NetDeviceContainer

        mobilityAdhoc = ns.mobility.MobilityHelper()
        streamIndex = 0  # used to get consistent mobility across scenarios

        pos = ns.core.ObjectFactory()
        pos.SetTypeId("ns3::RandomRectanglePositionAllocator")
        pos.Set("X", ns.core.StringValue("ns3::UniformRandomVariable[Min=0.0|Max=300.0]"))
        pos.Set("Y", ns.core.StringValue("ns3::UniformRandomVariable[Min=0.0|Max=1500.0]"))

        # Same as: Ptr<PositionAllocator> taPositionAlloc = pos.Create ()->GetObject<PositionAllocator> ();
        taPositionAlloc = pos.Create().GetObject(
            ns.mobility.PositionAllocator.GetTypeId())  # type: Ptr<PositionAllocator>
        streamIndex += taPositionAlloc.AssignStreams(streamIndex)

        ssSpeed = "ns3::UniformRandomVariable[Min=0.0|Max=%s]" % self.m_node_speed
        ssPause = "ns3::ConstantRandomVariable[Constant=%s]" % self.m_node_pause

        mobilityAdhoc.SetMobilityModel("ns3::RandomWaypointMobilityModel",
                                       "Speed", ns.core.StringValue(ssSpeed),
                                       "Pause", ns.core.StringValue(ssPause),
                                       "PositionAllocator", ns.core.PointerValue(taPositionAlloc))
        mobilityAdhoc.SetPositionAllocator(taPositionAlloc)
        mobilityAdhoc.Install(adhocNodes)
        streamIndex += mobilityAdhoc.AssignStreams(adhocNodes, streamIndex)
        # NS_UNUSED(streamIndex) # From this point, streamIndex is unused

        aodv = ns.aodv.AodvHelper()
        olsr = ns.olsr.OlsrHelper()
        dsdv = ns.dsdv.DsdvHelper()
        dsr = ns.dsr.DsrHelper()
        dsrMain = ns.dsr.DsrMainHelper()
        list = ns.internet.Ipv4ListRoutingHelper()
        internet = ns.internet.InternetStackHelper()

        if self.m_protocol == 1:
            list.Add(olsr, 100)
            self.m_protocolName = "OLSR"
        elif self.m_protocol == 2:
            list.Add(aodv, 100)
            self.m_protocolName = "AODV"
        elif self.m_protocol == 3:
            list.Add(dsdv, 100)
            self.m_protocolName = "DSDV"
        elif self.m_protocol == 4:
            self.m_protocolName = "DSR"
        else:
            print("No such protocol:%s" % str(self.m_protocol))  # NS_FATAL_ERROR ("No such protocol:" << m_protocol);

        if self.m_protocol < 4:
            internet.SetRoutingHelper(list)
            internet.Install(adhocNodes)
        elif self.m_protocol == 4:
            internet.Install(adhocNodes)
            dsrMain.Install(dsr, adhocNodes)

        print("assigning ip address") 

        addressAdhoc = ns.internet.Ipv4AddressHelper()
        addressAdhoc.SetBase(ns.network.Ipv4Address("10.1.1.0"), ns.network.Ipv4Mask("255.255.255.0"))
        adhocInterfaces = addressAdhoc.Assign(adhocDevices)

        onoff1 = ns.applications.OnOffHelper("ns3::UdpSocketFactory", ns.network.Address())
        onoff1.SetAttribute("OnTime", ns.core.StringValue("ns3::ConstantRandomVariable[Constant=1.0]"))
        onoff1.SetAttribute("OffTime", ns.core.StringValue("ns3::ConstantRandomVariable[Constant=0.0]"))

        for i in range(0, self.m_nSinks):
            # Ptr<Socket> sink = SetupPacketReceive (adhocInterfaces.GetAddress (i), adhocNodes.Get (i));
            sink = self.SetupPacketReceive(adhocInterfaces.GetAddress(i), adhocNodes.Get(i))

            remoteAddress = ns.network.AddressValue(
                ns.network.InetSocketAddress(adhocInterfaces.GetAddress(i), self.port))
            onoff1.SetAttribute("Remote", remoteAddress);

            # Ptr<UniformRandomVariable> var = CreateObject<UniformRandomVariable> ();
            posURV = ns.core.ObjectFactory()
            posURV.SetTypeId("ns3::UniformRandomVariable")
            var = posURV.Create().GetObject(ns.core.UniformRandomVariable.GetTypeId())

            temp = onoff1.Install(adhocNodes.Get(i + self.m_nSinks))  # type: ApplicationContainer
            temp.Start(ns.core.Seconds(var.GetValue(100.0, 101.0)))
            temp.Stop(ns.core.Seconds(self.m_total_time))

        ss = self.m_nSinks
        nodes = str(ss)

        ss2 = self.m_node_speed
        sNodeSpeed = str(ss2)

        ss3 = self.m_node_pause
        sNodePause = str(ss3)

        ss4 = rate
        sRate = str(ss4)

        tr_name = tr_name + "_" + \
                  self.m_protocolName + "_" + \
                  nodes + "sinks_" + \
                  sNodeSpeed + "speed_" + \
                  sNodePause + "pause_" + \
                  sRate + "rate"

        self.m_CSVfileName = tr_name

        ascii = ns.network.AsciiTraceHelper()
       
        ns.mobility.MobilityHelper.EnableAsciiAll(ascii.CreateFileStream(os.path.join(__workdir__, "%s.mob" % tr_name)))

       
        flowmon_helper = ns.flow_monitor.FlowMonitorHelper()
       
        monitor = flowmon_helper.InstallAll()
        monitor = flowmon_helper.GetMonitor()
        monitor.SetAttribute("DelayBinWidth", ns.core.DoubleValue(0.001))
        monitor.SetAttribute("JitterBinWidth", ns.core.DoubleValue(0.001))
        monitor.SetAttribute("PacketSizeBinWidth", ns.core.DoubleValue(20))

        print("Run Simulation.")

        self.WriteHeaderCsv()
        self.CheckThroughput()

        ns.core.Simulator.Stop(ns.core.Seconds(self.m_total_time))
        ns.core.Simulator.Run()

        monitor.CheckForLostPackets()
        classifier = flowmon_helper.GetClassifier()

        if self.m_debugger:
            for flow_id, flow_stats in monitor.GetFlowStats():

                with open(os.path.join(__workdir__, (self.m_CSVfileName + ".txt")), 'a') as file:
                   
                    t = classifier.FindFlow(flow_id)
                    proto = {6: 'TCP', 17: 'UDP'}[t.protocol]
                    file.write("FlowID: %i (%s %s/%s --> %s/%i)\n" % \
                      (flow_id, proto, t.sourceAddress, t.sourcePort, t.destinationAddress, t.destinationPort))
                    self.print_stats(file, flow_stats)
                    file.close()

        monitor.SerializeToXmlFile(os.path.join(__workdir__, "%s.flowmon" % tr_name), True, True)

        delays = []
        for flow_id, flow_stats in monitor.GetFlowStats():
            tupl = classifier.FindFlow(flow_id)
            if tupl.protocol == 17 and tupl.sourcePort == 698:
                continue

            if flow_stats.rxPackets == 0:
                delays.append(0)
            else:
                delays.append(flow_stats.delaySum.GetSeconds() / flow_stats.rxPackets)

        plt.hist(delays, 20)
        plt.xlabel("Delay (s)")
        plt.ylabel("Number of Flows")
        plt.savefig(os.path.join(__workdir__, '%s.png' % tr_name), dpi=75)
        plt.show()

        ns.core.Simulator.Destroy()


if __name__ == "__main__":
    v = RoutingExperiment()
    if len(sys.argv) == 1:
        v.Run()
    if len(sys.argv) == 2:
        v.Run(nSinks=(sys.argv[1]))
    if len(sys.argv) == 3:
        v.Run(nSinks=int(sys.argv[1]), txp=float(sys.argv[2]))
    if len(sys.argv) == 4:
        v.Run(nSinks=int(sys.argv[1]), txp=float(sys.argv[2]), TotalTime=int(sys.argv[3]), Nodes=int(sys.argv[4]))
    if len(sys.argv) == 5:
        v.Run(nSinks=int(sys.argv[1]),
              txp=float(sys.argv[2]),
              TotalTime=int(sys.argv[3]),
              Nodes=int(sys.argv[4]),
              Protocol=int(sys.argv[5]))
    if len(sys.argv) == 6:
        v.Run(nSinks=int(sys.argv[1]),
              txp=float(sys.argv[2]),
              TotalTime=int(sys.argv[3]),
              Nodes=int(sys.argv[4]),
              Protocol=int(sys.argv[5]),
              NodeSpeed=int(sys.argv[6]))
    if len(sys.argv) == 7:
        v.Run(nSinks=int(sys.argv[1]),
              txp=float(sys.argv[2]),
              TotalTime=int(sys.argv[3]),
              Nodes=int(sys.argv[4]),
              Protocol=int(sys.argv[5]),
              NodeSpeed=int(sys.argv[6]),
              NodePause=int(sys.argv[7]))
    if len(sys.argv) == 8:
        v.Run(nSinks=int(sys.argv[1]),
              txp=float(sys.argv[2]),
              TotalTime=int(sys.argv[3]),
              Nodes=int(sys.argv[4]),
              Protocol=int(sys.argv[5]),
              NodeSpeed=int(sys.argv[6]),
              NodePause=int(sys.argv[7]),
              CSVfileName=sys.argv[8])
