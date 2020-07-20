/* This file is part of openGalaxy.
 *
 * opengalaxy - a SIA receiver for Galaxy security control panels.
 * Copyright (C) 2015 - 2019 Alexander Bruines <alexander.bruines@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * as published by the Free Software Foundation, or (at your option)
 * any later version.
 *
 * In addition, as a special exception, the author of this program
 * gives permission to link the code of its release with the OpenSSL
 * project's "OpenSSL" library (or with modified versions of it that
 * use the same license as the "OpenSSL" library), and distribute the
 * linked executables. You must obey the GNU General Public License
 * in all respects for all of the code used other than "OpenSSL".
 * If you modify this file, you may extend this exception to your
 * version of the file, but you are not obligated to do so.
 * If you do not wish to do so, delete this exception statement
 * from your version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

 /* For libwebsockets API v2.??? (master) */

#include "atomic.h"
#include "opengalaxy.hpp"

namespace openGalaxy {

#define VPRINTF(...) printf(__VA_ARGS__)

//#define EXTRA_VERBOSE 1
#undef EXTRA_VERBOSE

#ifdef EXTRA_VERBOSE
static const char *reason2txt(int reason)
{
  switch(reason){
    case LWS_CALLBACK_ESTABLISHED: return "LWS_CALLBACK_ESTABLISHED";
    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR: return "LWS_CALLBACK_CLIENT_CONNECTION_ERROR";
    case LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH: return "LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH";
    case LWS_CALLBACK_CLIENT_ESTABLISHED: return "LWS_CALLBACK_CLIENT_ESTABLISHED";
    case LWS_CALLBACK_CLOSED: return "LWS_CALLBACK_CLOSED";
    case LWS_CALLBACK_CLOSED_HTTP: return "LWS_CALLBACK_CLOSED_HTTP";
    case LWS_CALLBACK_RECEIVE: return "LWS_CALLBACK_RECEIVE";
    case LWS_CALLBACK_RECEIVE_PONG: return "LWS_CALLBACK_RECEIVE_PONG";
    case LWS_CALLBACK_CLIENT_RECEIVE: return "LWS_CALLBACK_CLIENT_RECEIVE";
    case LWS_CALLBACK_CLIENT_RECEIVE_PONG: return "LWS_CALLBACK_CLIENT_RECEIVE_PONG";
    case LWS_CALLBACK_CLIENT_WRITEABLE: return "LWS_CALLBACK_CLIENT_WRITEABLE";
    case LWS_CALLBACK_SERVER_WRITEABLE: return "LWS_CALLBACK_SERVER_WRITEABLE";
    case LWS_CALLBACK_HTTP: return "LWS_CALLBACK_HTTP";
    case LWS_CALLBACK_HTTP_BODY: return "LWS_CALLBACK_HTTP_BODY";
    case LWS_CALLBACK_HTTP_BODY_COMPLETION: return "LWS_CALLBACK_HTTP_BODY_COMPLETION";
    case LWS_CALLBACK_HTTP_FILE_COMPLETION: return "LWS_CALLBACK_HTTP_FILE_COMPLETION";
    case LWS_CALLBACK_HTTP_WRITEABLE: return "LWS_CALLBACK_HTTP_WRITEABLE";
    case LWS_CALLBACK_FILTER_NETWORK_CONNECTION: return "LWS_CALLBACK_FILTER_NETWORK_CONNECTION";
    case LWS_CALLBACK_FILTER_HTTP_CONNECTION: return "LWS_CALLBACK_FILTER_HTTP_CONNECTION";
    case LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED: return "LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED";
    case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION: return "LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION";
    case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS: return "LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS";
    case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS: return "LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS";
    case LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION: return "LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION";
    case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: return "LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER";
    case LWS_CALLBACK_CONFIRM_EXTENSION_OKAY: return "LWS_CALLBACK_CONFIRM_EXTENSION_OKAY";
    case LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED: return "LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED";
    case LWS_CALLBACK_PROTOCOL_INIT: return "LWS_CALLBACK_PROTOCOL_INIT";
    case LWS_CALLBACK_PROTOCOL_DESTROY: return "LWS_CALLBACK_PROTOCOL_DESTROY";
    case LWS_CALLBACK_WSI_CREATE: return "LWS_CALLBACK_WSI_CREATE";
    case LWS_CALLBACK_WSI_DESTROY: return "LWS_CALLBACK_WSI_DESTROY";
    case LWS_CALLBACK_GET_THREAD_ID: return "LWS_CALLBACK_GET_THREAD_ID";
    case LWS_CALLBACK_ADD_POLL_FD: return "LWS_CALLBACK_ADD_POLL_FD";
    case LWS_CALLBACK_DEL_POLL_FD: return "LWS_CALLBACK_DEL_POLL_FD";
    case LWS_CALLBACK_CHANGE_MODE_POLL_FD: return "LWS_CALLBACK_CHANGE_MODE_POLL_FD";
    case LWS_CALLBACK_LOCK_POLL: return "LWS_CALLBACK_LOCK_POLL";
    case LWS_CALLBACK_UNLOCK_POLL: return "LWS_CALLBACK_UNLOCK_POLL";
    case LWS_CALLBACK_OPENSSL_CONTEXT_REQUIRES_PRIVATE_KEY: return "LWS_CALLBACK_OPENSSL_CONTEXT_REQUIRES_PRIVATE_KEY";
    case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE: return "LWS_CALLBACK_WS_PEER_INITIATED_CLOSE";
    case LWS_CALLBACK_WS_EXT_DEFAULTS: return "LWS_CALLBACK_WS_EXT_DEFAULTS";
    case LWS_CALLBACK_CGI: return "LWS_CALLBACK_CGI";
    case LWS_CALLBACK_CGI_TERMINATED: return "LWS_CALLBACK_CGI_TERMINATED";
    case LWS_CALLBACK_CGI_STDIN_DATA: return "LWS_CALLBACK_CGI_STDIN_DATA";
    case LWS_CALLBACK_CGI_STDIN_COMPLETED: return "LWS_CALLBACK_CGI_STDIN_COMPLETED";
    case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP: return "LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP";
    case LWS_CALLBACK_CLOSED_CLIENT_HTTP: return "LWS_CALLBACK_CLOSED_CLIENT_HTTP";
    case LWS_CALLBACK_RECEIVE_CLIENT_HTTP: return "LWS_CALLBACK_RECEIVE_CLIENT_HTTP";
    case LWS_CALLBACK_COMPLETED_CLIENT_HTTP: return "LWS_CALLBACK_COMPLETED_CLIENT_HTTP";
    case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ: return "LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ";
    case LWS_CALLBACK_HTTP_BIND_PROTOCOL: return "LWS_CALLBACK_HTTP_BIND_PROTOCOL";
    case LWS_CALLBACK_HTTP_DROP_PROTOCOL: return "LWS_CALLBACK_HTTP_DROP_PROTOCOL";
    case LWS_CALLBACK_CHECK_ACCESS_RIGHTS: return "LWS_CALLBACK_CHECK_ACCESS_RIGHTS";
    case LWS_CALLBACK_PROCESS_HTML: return "LWS_CALLBACK_PROCESS_HTML";
    case LWS_CALLBACK_ADD_HEADERS: return "LWS_CALLBACK_ADD_HEADERS";
    case LWS_CALLBACK_SESSION_INFO: return "LWS_CALLBACK_SESSION_INFO";
    case LWS_CALLBACK_GS_EVENT: return "LWS_CALLBACK_GS_EVENT";
    case LWS_CALLBACK_HTTP_PMO: return "LWS_CALLBACK_HTTP_PMO";
    case LWS_CALLBACK_USER: return "LWS_CALLBACK_USER";
  }
  return "LWS_??????????";
}
#endif

static void get_headers(struct lws *wsi, std::string& ref, std::string& del)
{
  int n = 0;
  char buf[8192];
  const unsigned char *c;

  do {
    c = lws_token_to_string((lws_token_indexes)n);
    if(!c){
      n++;
      continue;
    }

    if (!lws_hdr_total_length(wsi, (lws_token_indexes)n)) {
      n++;
      continue;
    }

    lws_hdr_copy(wsi, buf, sizeof buf, (lws_token_indexes)n);

    if(n == WSI_TOKEN_HTTP_REFERER){ // referer
      ref.assign(buf);
    }

    if(n == WSI_TOKEN_HTTP_URI_ARGS){ // delete
      del.assign(buf);
    }

    n++;
  } while (c);
}


static const char *get_http_mimetype(const char *file)
{
  int n = strlen(file);
  if(n < 5) return nullptr;
  if(!strcmp(&file[n - 4], ".ico")) return "image/x-icon";
  if(!strcmp(&file[n - 3], ".js")) return "text/javascript";
  if(!strcmp(&file[n - 4], ".css")) return "text/css";
  if(!strcmp(&file[n - 4], ".png")) return "image/png";
  if(!strcmp(&file[n - 4], ".jpg")) return "image/jpeg";
  if(!strcmp(&file[n - 5], ".html")) return "text/html";
  return nullptr;
}


static inline int try_to_reuse(struct lws *wsi)
{
  return (lws_http_transaction_completed(wsi)) ? -1 : 0;
}


// static function:
// libwebsockets callback for the openGalaxy::HTTP protocol
#define LOGE(...) ctxpss->websocket->opengalaxy().syslog().error(__VA_ARGS__)
#define LOGD(...) ctxpss->websocket->opengalaxy().syslog().debug(__VA_ARGS__)
int Websocket::http_protocol_callback(
  struct lws *wsi,
  enum lws_callback_reasons reason,
  void *user,
  void *in,
  size_t len
){
  int n = 0; // The result to return.
  const char *mimetype;
  int m;

  // We do not want the browser to cache (some of) our files,
  // these http header seem to work the best.
  const char *nocache_headers =
    "Cache-Control: no-cache, no-store, must-revalidate\x0d\x0a" // HTTP 1.1
    "Pragma: no-cache\x0d\x0a" // HTTP 1.0
    "Expires: 0\x0d\x0a"; // Proxies

  char *other_headers = nullptr;

  struct per_session_data_http_protocol *pss = (struct per_session_data_http_protocol *)user;
  struct lws_context *context = nullptr;
  ContextUserData *ctxpss = nullptr;
  Session *s = nullptr;

#ifdef EXTRA_VERBOSE
if(reason == LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS) pss = nullptr;
if(reason == LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION) pss = nullptr;
if(wsi && pss) context = lws_get_context(wsi);
if(context) ctxpss = (ContextUserData *) lws_context_user(context);
if(
 ( reason != LWS_CALLBACK_GET_THREAD_ID )&&
 ( reason != LWS_CALLBACK_LOCK_POLL )&&
 ( reason != LWS_CALLBACK_ADD_POLL_FD )&&
 ( reason != LWS_CALLBACK_UNLOCK_POLL )&&
 ( reason != LWS_CALLBACK_CHANGE_MODE_POLL_FD )&&
 ( reason != LWS_CALLBACK_WSI_CREATE )&&
 ( reason != LWS_CALLBACK_DEL_POLL_FD )&&
 ( reason != LWS_CALLBACK_WSI_DESTROY )&&
 ( reason != LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED )//&&
){
  VPRINTF("%s {\n",reason2txt(reason));
#if 0
  if(pss){
    VPRINTF(" pss = %p\n", pss);
    VPRINTF(" pss.session.id = %llu\n", pss->session.id);
  }
  else {
    VPRINTF(" pss = %p\n", pss);
  }

  if(ctxpss){
    VPRINTF(" ctxpss = %p\n", ctxpss);
    VPRINTF(" ctxpss.sessions.size() = %d\n", ctxpss->sessions.size());
  } else {
    VPRINTF(" ctxpss = %p\n", ctxpss);
  }

#endif
}
#endif

  switch(reason){

    // Load the SSL certificates needed for verifying client certificates
    case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS: {
      context = lws_get_context(wsi);
      ctxpss = (ContextUserData *) lws_context_user(context);

      if(ctxpss && ctxpss->websocket->opengalaxy().m_options.no_ssl == 0){
        n = ssl_load_certs((SSL_CTX*)user, context); // load Certificate Revocation List.
      }
      break;
    }

    // Verify a client SSL certificate
    // Note: The wsi if 'faked' and is only able to get the context...
    case LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION: {
      context = lws_get_context(wsi); 
      ctxpss = (ContextUserData *) lws_context_user(context);

      // First check if this is a valid certificate
      n = ssl_verify_client_cert(context, (SSL*)in, (X509_STORE_CTX*)user, len);
      if(n){
        // The certificate is invalid: blacklist the ip address for a while
        ctxpss = (ContextUserData *) lws_context_user(context);
        LOGE("Websocket: Failed to verify client SSL certificate, blacklisting IP address: %s", ctxpss->websocket->http_last_client_ip);
        ctxpss->websocket->opengalaxy().websocket().blacklist.append(
          new class BlacklistedIpAddress(
            ctxpss->websocket->http_last_client_ip,
            ctxpss->websocket->opengalaxy().settings().blacklist_timeout_minutes
        ));
        //ctxpss->websocket->opengalaxy().galaxy()
        //  .GenerateWrongCodeAlarm_nb(Galaxy::sia_module::rs232, Websocket::blacklist_dummy_callback);
      }
      break;
    }

    // Who is it? Get peer IP address (for use in LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION)
    // This is also where we block blacklisted IP addresses.
    case LWS_CALLBACK_FILTER_NETWORK_CONNECTION: {
      context = lws_get_context(wsi);
      ctxpss = (ContextUserData *) lws_context_user(context);
      // Clear last client name/ipaddress
      ctxpss->websocket->http_last_client_name[0] = '\0';
      ctxpss->websocket->http_last_client_ip[0] = '\0';
      // Retrieve the client name/ipaddress
      lws_get_peer_addresses(
        wsi,
        *((int*)(&in)),
        ctxpss->websocket->http_last_client_name,
        sizeof ctxpss->websocket->http_last_client_name,
        ctxpss->websocket->http_last_client_ip,
        sizeof ctxpss->websocket->http_last_client_ip
      );
      // Compare them against the list of blacklisted addresses.
      for(int t = 0; t < ctxpss->websocket->opengalaxy().websocket().blacklist.size(); t++){
        if(!ctxpss->websocket->opengalaxy().websocket().blacklist[t]->ip.compare(ctxpss->websocket->http_last_client_ip)){
          // Block the connection if a match is found.
          LOGE("Websocket: Blocking connection attempt from blacklisted IP address: %s", ctxpss->websocket->http_last_client_ip);
          n = 1;
          break;
        }
      }
      break;
    }

    // While uploading certificates openGalaxyCA connects to this protocol as client.
    // Since libwebsockets cannot function as a http client and only as websocket client
    // we connecct to the http protocol using a websocket and end up here.
    case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
      // All that needs to be done here is to fall through to the
      // handler normaly used for LWS_CALLBACK_HTTP_BIND_PROTOCOL
      // so that a session is started.

    // Sets Session::http_connected to true,
    // and puts a reference to the Session in the pss
    case LWS_CALLBACK_HTTP_BIND_PROTOCOL: {
      context = lws_get_context(wsi);
      ctxpss = (ContextUserData *) lws_context_user(context);
      // We only use sessions if we use both SSL and client certificates.
      if(ctxpss->websocket->opengalaxy().m_options.no_ssl == 0){
        if(ctxpss->websocket->opengalaxy().m_options.no_client_certs == 0){
          // Start/retrieve session
          n = Session::start(wsi, pss->session, &s);
          if(n){
            LOGE("Websocket: Could not start a new Session!");
            break;
          }
          // Set the session status for this protocol to 'connected'
          s->http_connected = 1;
        }
      }
      break;
    }

    // Sets Session::http_connected to false
    // We must do this without using the pss bacause
    // its content is no longer valid at this point.
    case LWS_CALLBACK_CLOSED:         // opened as websocket
    case LWS_CALLBACK_CLOSED_HTTP: {  // opened as http
      context = lws_get_context(wsi);
      ctxpss = (ContextUserData *) lws_context_user(context);

      if(ctxpss->websocket->opengalaxy().m_options.no_ssl == 0){
        if(ctxpss->websocket->opengalaxy().m_options.no_client_certs == 0){

          // Retrieve session
          s = Session::get(wsi);
          if(!s){
            LOGE("Websocket: Could not retrieve Session!");
            n = 1;
            break;
          }

          // Set the session status for this protocol to 'disconnected'
          s->http_connected = 0;
        }
      }

      break;
    }


    // Handles HTTP requests (ie. serving a file)
    case LWS_CALLBACK_HTTP: {

      context = lws_get_context(wsi);
      ctxpss = (ContextUserData *) lws_context_user(context);

      // sanity check len
      if(len < 1){
        lws_return_http_status(wsi, HTTP_STATUS_BAD_REQUEST, nullptr);
        n = try_to_reuse(wsi);
        break;
      }

      // DELETE and REFERE http headers
      std::string http_delete;
      std::string http_referer;

      // If both SSL and client certificates are in use:
      if((ctxpss->websocket->opengalaxy().m_options.no_ssl == 0) &&
        (ctxpss->websocket->opengalaxy().m_options.no_client_certs == 0)){

        unsigned char *p;
        unsigned long long int s_id;

        // Retrieve the Session using its id stored in the pss
        s = Session::get(pss->session, context);
        if(!s){
          // Use a slower method as fallback (locate by peer certificate)
          s = Session::get(wsi);
        }

        if(!s){
          // No session found!
          ctxpss->websocket->opengalaxy().syslog().error("Websocket: Warning, no Session data in LWS_CALLBACK_HTTP!");
          lws_return_http_status(wsi, HTTP_STATUS_FORBIDDEN, "No such session!");
          n = -1;
          break;
        }

        // Require a password?
        if(ctxpss->websocket->opengalaxy().m_options.no_password == 0){
          // Yes, get the client's authentication info
          if(!s->auth){
            // No authentication info found, cannot continue.
            lws_return_http_status(wsi, HTTP_STATUS_FORBIDDEN, "Not authorized!");
            n = try_to_reuse(wsi);
            break;
          }
        }

        // Get the session id from the query string
        // (ie. get it from the DELETE http header).
        get_headers(wsi, http_referer, http_delete);
        s_id = 0;
        int pos = http_delete.find(Session::query_string);
        if((unsigned)pos != std::string::npos){
          char *str = (char*)http_delete.c_str();
          s_id = strtoull((char*)&str[pos+strlen(Session::query_string)], nullptr, 16);
        }

        // Starting a new session? ie. is /index.html requested
        if(
          (strcmp((const char*)in, "/") == 0) ||
          (strcmp((const char*)in, ctxpss->websocket->www_root_document) == 0)
        ){
          // Yes /index.html is requested,
          // allready redirected to a new session?
          if(!s->session_starting && !s->session_was_started){
            // no not yet redirected,
            // Yes this is a new session, redirect to the new URI
            s->logoff();
            s->session_starting = 1;
            ssl_rand_pseudo_bytes((unsigned char*)&s->session.id, sizeof(s->session.id));
            p = ctxpss->websocket->http_file_buffer + LWS_SEND_BUFFER_PRE_PADDING;
            snprintf(
              ctxpss->websocket->http_path_buffer,
              sizeof(ctxpss->websocket->http_path_buffer),
              ctxpss->websocket->fmt_redirect_uri,
              ctxpss->websocket->www_root_document,
              Session::query_string,
              s->session.id
            );
            unsigned char *end = p + sizeof(ctxpss->websocket->http_file_buffer) - LWS_SEND_BUFFER_PRE_PADDING;
            if(lws_add_http_header_status(wsi, HTTP_STATUS_TEMPORARY_REDIRECT, &p, end)){
              n = 1;
              break;
            }
            if(lws_add_http_header_by_name( wsi, (unsigned char *)"Location:", (unsigned char *)ctxpss->websocket->http_path_buffer, strlen(ctxpss->websocket->http_path_buffer), &p, end)){
              n = 1;
              break;
            }
            if(lws_add_http_header_content_length(wsi, 0, &p, end)){
              n = 1;
              break;
            }
            if(lws_finalize_http_header(wsi, &p, end)){
              n = 1;
              break;
            }
            LOGD("Session: Redirecting %s to a new session with id: %llX", s->auth->fullname().c_str(), s->session.id);
            n = lws_write(
              wsi,
              ctxpss->websocket->http_file_buffer + LWS_SEND_BUFFER_PRE_PADDING,
              p - (ctxpss->websocket->http_file_buffer + LWS_SEND_BUFFER_PRE_PADDING),
              LWS_WRITE_HTTP_HEADERS
            );
            break;
          }
          else {
            s->session_starting = 0;
            // yes allready redirected,
            // there should be a valid session id in the query string
            if(s_id != s->session.id){
              s->logoff();
              // No valid s_id, start a new session
              s->session_starting = 1;
              ssl_rand_pseudo_bytes((unsigned char*)&s->session.id, sizeof(s->session.id));
              p = ctxpss->websocket->http_file_buffer + LWS_SEND_BUFFER_PRE_PADDING;
              snprintf(
                ctxpss->websocket->http_path_buffer,
                sizeof(ctxpss->websocket->http_path_buffer),
                ctxpss->websocket->fmt_redirect_uri,
                ctxpss->websocket->www_root_document,
                Session::query_string,
                s->session.id
              );
              unsigned char *end = p + sizeof(ctxpss->websocket->http_file_buffer) - LWS_SEND_BUFFER_PRE_PADDING;
              if(lws_add_http_header_status(wsi, HTTP_STATUS_TEMPORARY_REDIRECT, &p, end)){
                n = 1;
                break;
              }
              if(lws_add_http_header_by_name(wsi, (unsigned char *)"Location:", (unsigned char *)ctxpss->websocket->http_path_buffer, strlen(ctxpss->websocket->http_path_buffer), &p, end)){
                n = 1;
                break;
              }
              if(lws_add_http_header_content_length(wsi, 0, &p, end)){
                n = 1;
                break;
              }
              if(lws_finalize_http_header(wsi, &p, end)){
                n = 1;
                break;
              }
              LOGD("Session: Redirecting %s to session id: %llX", s->auth->fullname().c_str(), s->session.id);
              n = lws_write(
                wsi,
                ctxpss->websocket->http_file_buffer + LWS_SEND_BUFFER_PRE_PADDING,
                p - (ctxpss->websocket->http_file_buffer + LWS_SEND_BUFFER_PRE_PADDING),
                LWS_WRITE_HTTP_HEADERS
              );
              break;
            }
            // Session id's match
            s->session_was_started = 1;
          }
        }
        // No index.html was not requested, another file is.
        else {
          s->session_was_started = 0;
        }

        // If the URI does not have a (valid) session id in the query string,
        // but does have a session id appended to the REFERER header, then
        // use a server redirect to the url with !that! session id appended
        // to the query string.
        if(s_id != s->session.id){
          int pos = http_referer.find(Session::query_string);
          if((unsigned)pos != std::string::npos){
            char *str = (char*)http_referer.c_str();
            s_id = strtoull((char*)&str[pos+strlen(Session::query_string)], nullptr, 16);
            if(s_id != 0){
              p = ctxpss->websocket->http_file_buffer + LWS_SEND_BUFFER_PRE_PADDING;
              snprintf(
                ctxpss->websocket->http_path_buffer,
                sizeof(ctxpss->websocket->http_path_buffer),
                ctxpss->websocket->fmt_redirect_uri,
                (char*)in,
                Session::query_string,
                s_id
              );
              unsigned char *end = p + sizeof(ctxpss->websocket->http_file_buffer) - LWS_SEND_BUFFER_PRE_PADDING;
              if(lws_add_http_header_status(wsi, HTTP_STATUS_TEMPORARY_REDIRECT, &p, end)){
                n = 1;
                break;
              }
              if(lws_add_http_header_by_name(wsi, (const unsigned char *)"Location:", (unsigned char *)ctxpss->websocket->http_path_buffer, strlen(ctxpss->websocket->http_path_buffer), &p, end)){
                n = 1;
                break;
              }
              if(lws_add_http_header_content_length(wsi, 0, &p, end)){
                n = 1;
                break;
              }
              if(lws_finalize_http_header(wsi, &p, end)){
                n = 1;
                break;
              }
              n = lws_write(
                wsi,
                ctxpss->websocket->http_file_buffer + LWS_SEND_BUFFER_PRE_PADDING,
                p - (ctxpss->websocket->http_file_buffer + LWS_SEND_BUFFER_PRE_PADDING),
                LWS_WRITE_HTTP_HEADERS
              );
              break;
            }
            else {
              // No session id at all
              // block serving the file but make an exception for /favicon.ico (firefox)
              if(strcmp("/favicon.ico",(char*)in)!=0){
                s->logoff();
                LOGD("Session: no valid session whilst serving \"%s\", blocking!", (char*)in);
                lws_return_http_status(wsi, HTTP_STATUS_FORBIDDEN, "You do not own this session!");
                n = 1;
                break;
              }
              // fall through
            }
          }
        }

        // If the session does not match
        // block serving the file but make an exception for /favicon.ico
        // (firefox does not add the REFERER tag when requesting this file)
        if(s_id != s->session.id){
          if(strcmp("/favicon.ico",(char*)in)!=0){
            s->logoff();
            LOGE("Session: session mismatch, blocking!");
            lws_return_http_status(wsi, HTTP_STATUS_FORBIDDEN, "You do not own this session!");
            n = 1;
            break;
          }
        }

        // Valid session, reset the 'unused session' timeout timer
        s->timeout_tp = std::chrono::high_resolution_clock::now();

        // Reset the activity timeout for this session
        s->set_active();
      }

      //
      // At this point we are ready to handle the http request (ie. serve a file).
      //

      // We do not accept post data.
      if(lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI)){
        n = 1;
        break;
      }

      // This server has no knowledge of directories,
      // only serve files that were explicitly approved by us.
      for(m = 0, n = 1; ctxpss->websocket->valid_files_to_serve[m]; m++){
        n = strcmp((char*)in + 1, ctxpss->websocket->valid_files_to_serve[m]);
        if(n == 0) break;
      }
      if(n != 0){
        LOGE("Websocket: HTTP GET Request denied for unregistered file: '%s'", (char*)in);
        lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, "Not a registered file.");
        n = try_to_reuse(wsi);
        break;
      }

      // Found the file in the whitelist, do we allow the browser to cache this file?
      // Add some extra http headers to the reply if we do not.
      if(ctxpss->websocket->valid_files_to_cache[m] == 0) other_headers = (char*)nocache_headers;

      // Compile a path to the file to serve in http_path_buffer:
      // Start with the location of the WWW directory.
      strncpy(ctxpss->websocket->http_path_buffer, ctxpss->websocket->path_www_root.data(), sizeof(ctxpss->websocket->http_path_buffer));
      // Is a specific file requested? (ie. not the root document)
      if(strcmp((const char*)in, "/")){
        // No, its another file. Append the filename to the path.
        if(*((const char *)in) != '/') strcat(ctxpss->websocket->http_path_buffer, "/");
        strncat(ctxpss->websocket->http_path_buffer, (const char*)in, sizeof(ctxpss->websocket->http_path_buffer) - 1 - ctxpss->websocket->path_www_root.size());
      }
      else {
        // Yes, the root document (/) is requested.
        // Append the default filename (index.html) to the path.
        strncat(ctxpss->websocket->http_path_buffer, ctxpss->websocket->www_root_document, sizeof(ctxpss->websocket->http_path_buffer) - 1);
      }
      // Finally close the path with a 0 byte.
      ctxpss->websocket->http_path_buffer[sizeof(ctxpss->websocket->http_path_buffer) - 1] = '\0';

      // Determine the MIME type of the file to serve
      mimetype = get_http_mimetype(ctxpss->websocket->http_path_buffer);

      // Check the MIME type and refuse to serve files we don't understand.
      if(!mimetype){
        LOGE("Websocket: Unknown mimetype for %s", ctxpss->websocket->http_path_buffer);
        lws_return_http_status(wsi, HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE, "Unsupported MIME type!");
        n = -1;
        break;
      }

      // Serve the file to the client.
	  n = lws_serve_http_file(
        wsi,
        ctxpss->websocket->http_path_buffer,
        mimetype,
        other_headers,
        (other_headers) ? strlen(other_headers) : 0
      );

      // Error serving the file?
      if(n < 0){
        // Yes, close the socket.
        LOGE("Websocket: Failed to serve file: %s", ctxpss->websocket->http_path_buffer);
        break;
      }

      // n==0 means the transfer has started
      // n>0 means the file was completely transfered,
      // if the http transaction is also complete we can close the socket.
	  if((n > 0) && lws_http_transaction_completed(wsi)){
        // Close the socket.
        n = -1;
        break;
      }

      // Notice that the sending of the file completes asynchronously,
      // We must return 0 to let it complete.
      // We'll get a LWS_CALLBACK_HTTP_FILE_COMPLETION callback when it's done.
      n = 0;
      break;
    }

    default:
      break;
  }

#ifdef EXTRA_VERBOSE
if(
 ( reason != LWS_CALLBACK_GET_THREAD_ID )&&
 ( reason != LWS_CALLBACK_LOCK_POLL )&&
 ( reason != LWS_CALLBACK_ADD_POLL_FD )&&
 ( reason != LWS_CALLBACK_UNLOCK_POLL )&&
 ( reason != LWS_CALLBACK_CHANGE_MODE_POLL_FD )&&
 ( reason != LWS_CALLBACK_WSI_CREATE )&&
 ( reason != LWS_CALLBACK_DEL_POLL_FD )&&
 ( reason != LWS_CALLBACK_WSI_DESTROY )&&
 ( reason != LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED )
){
  VPRINTF("}\n");
}
#endif

  // Return with the status set during switch(reason){}
  return n;
}
#undef LOGE
#undef LOGD


} // ends namespace openGalaxy

