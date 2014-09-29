package tlc

import dispatch._
import java.util.Date
import javax.net.ssl.SSLSession
import java.security.cert.{ CertificateNotYetValidException, CertificateExpiredException, X509Certificate }
import com.ning.http.util.AllowAllHostnameVerifier
import scala.concurrent.Promise
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.duration.FiniteDuration

object Check {
  sealed trait Result
  case object Ok extends Result
  case object NotYet extends Result
  case object Expired extends Result
  case object None extends Result
}

case class Check(
  hosts: Iterable[String], after: FiniteDuration) {
  import Check._
  def check(): Map[String, Future[Check.Result]] = {
    val checks = hosts.map((_, Promise[Check.Result]())).toMap
    val client = new Http().configure(_.setHostnameVerifier(new AllowAllHostnameVerifier() {
      override def verify(hostname: String, session: SSLSession) = {
        checks(hostname).success(session.getPeerCertificates.headOption.collect {
          case cert: X509Certificate => 
            try {
              cert.checkValidity(new Date(System.currentTimeMillis() + after.toMillis))
              Ok
            } catch {
              case notyet: CertificateNotYetValidException => NotYet
              case expired: CertificateExpiredException    => Expired
            }
        } match {
          case None => Check.None
          case Some(c) => c
        })
        super.verify(hostname, session)
      }
    }))
    hosts.map( host => (host, client(:/(host, 443)).flatMap {
      case _ => checks(host).future
    })).toMap
  }
}
