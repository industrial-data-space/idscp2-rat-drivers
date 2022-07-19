package de.fhg.aisec.ids.snp

import io.grpc.netty.NettyChannelBuilder
import java.net.SocketAddress

internal class SnpAttestd(val address: SocketAddress) {
    private val channel = NettyChannelBuilder
        .forAddress(address)
        .usePlaintext()
        .build()

    val rpc = SnpAttestdServiceGrpc.newBlockingStub(channel)
}
