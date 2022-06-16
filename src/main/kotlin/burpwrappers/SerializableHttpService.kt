package burpwrappers

import burp.IHttpService
import java.io.Serializable

data class SerializableHttpService(override val host: String, override val port: Int, override val protocol: String): IHttpService, Serializable{
    companion object{
        fun fromHttpService(s: IHttpService): SerializableHttpService{
            return SerializableHttpService(s.host, s.port, s.protocol)
        }
    }
}