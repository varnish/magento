# VCL version marker. Has no correlation with the Varnish version. VCL version 4.1 requires Varnish 6 or higher
vcl 4.1;

# Import Varnish modules
import uri;
import urlplus;
import cookieplus;
import std;
import tls;
import ykey;
import activedns;
import udo;

# Access Control List (ACL) for cache invalidation access
acl purge {
    "localhost";
    "127.0.0.1";
    "::1";
    "172.18.0.0/24"; # Change this and add the right IP addresses & CIDRs
}

# Probe template, used by UDO
probe health {
    .url = "/health_check.php";
    .timeout = 2s;
    .interval = 5s;
    .window = 10;
    .threshold = 5;
}

# Backend template, used by UDO
backend default {
    .host = "0.0.0.0";
    .ssl = 1;
    .ssl_verify_host = 0;
    .ssl_verify_peer = 0;
    .ssl_sni = 1;
    .host_header = "example.com"; # Change this and add the right host header
    .first_byte_timeout = 600s;
}

# Initialize DNS-based dynamic backends
sub vcl_init {
    # Initialize DNS group with the right hostname and port number
    # Supports SRV, A and AAAA records
    new group = activedns.dns_group("magento.example.com:443"); # Change this and add the right backend hostname and port number
    # Only allow IPv4 addresses
    group.set_ipv_rule(ipv4);
    # Ignore DNS TTL from the DNS server and force it to 5 seconds
    group.set_ttl_rule(force);
    group.set_ttl(5s);
    # Assign backend and health probe templates
    # The DNS group will override the host and port number
    group.set_backend_template(default);
    group.set_probe_template(health);

    # Initiliaze a Unified Director Object (UDO)
    new magento = udo.director();
    # If the DNS record returns multiple values, perform random loadbalancing based on those values
    magento.set_type(random);
    # Subscribe to the DNS group to capture potential DNS changes
    magento.subscribe(group.get_tag());
}

sub vcl_backend_fetch {
    # Assign a backend dynamically using the Unified Director Object
    set bereq.backend = magento.backend();
}

sub vcl_backend_error {
    # Capture potential backend failures and retry on another server
    return (retry);
}

sub vcl_recv {
    # Remove all marketing get parameters to minimize the cache objects
    # You can add additional parameters that occur in your setup
    urlplus.query_delete("_branch_match_id");
    urlplus.query_delete("_bta_c");
    urlplus.query_delete("_bta_tid");
    urlplus.query_delete("_ga");
    urlplus.query_delete("_gl");
    urlplus.query_delete("_ke");
    urlplus.query_delete("_kx");
    urlplus.query_delete("campid");
    urlplus.query_delete("cof");
    urlplus.query_delete("customid");
    urlplus.query_delete("cx");
    urlplus.query_delete("dclid");
    urlplus.query_delete("dm_i");
    urlplus.query_delete("ef_id");
    urlplus.query_delete("epik");
    urlplus.query_delete("fbclid");
    urlplus.query_delete("gad_source");
    urlplus.query_delete("gbraid");
    urlplus.query_delete("gclid");
    urlplus.query_delete("gclsrc");
    urlplus.query_delete("gdffi");
    urlplus.query_delete("gdfms");
    urlplus.query_delete("gdftrk");
    urlplus.query_delete("hsa_acc");
    urlplus.query_delete("hsa_ad");
    urlplus.query_delete("hsa_cam");
    urlplus.query_delete("hsa_grp");
    urlplus.query_delete("hsa_kw");
    urlplus.query_delete("hsa_mt");
    urlplus.query_delete("hsa_net");
    urlplus.query_delete("hsa_src");
    urlplus.query_delete("hsa_tgt");
    urlplus.query_delete("hsa_ver");
    urlplus.query_delete("ie");
    urlplus.query_delete("igshid");
    urlplus.query_delete("irclickid");
    urlplus.query_delete("matomo_campaign");
    urlplus.query_delete("matomo_cid");
    urlplus.query_delete("matomo_content");
    urlplus.query_delete("matomo_group");
    urlplus.query_delete("matomo_keyword");
    urlplus.query_delete("matomo_medium");
    urlplus.query_delete("matomo_placement");
    urlplus.query_delete("matomo_source");
    urlplus.query_delete("mc_cid");
    urlplus.query_delete("mc_eid");
    urlplus.query_delete("mkcid");
    urlplus.query_delete("mkevt");
    urlplus.query_delete("mkrid");
    urlplus.query_delete("mkwid");
    urlplus.query_delete("msclkid");
    urlplus.query_delete("mtm_campaign");
    urlplus.query_delete("mtm_cid");
    urlplus.query_delete("mtm_content");
    urlplus.query_delete("mtm_group");
    urlplus.query_delete("mtm_keyword");
    urlplus.query_delete("mtm_medium");
    urlplus.query_delete("mtm_placement");
    urlplus.query_delete("mtm_source");
    urlplus.query_delete("nb_klid");
    urlplus.query_delete("ndclid");
    urlplus.query_delete("origin");
    urlplus.query_delete("pcrid");
    urlplus.query_delete("piwik_campaign");
    urlplus.query_delete("piwik_keyword");
    urlplus.query_delete("piwik_kwd");
    urlplus.query_delete("pk_campaign");
    urlplus.query_delete("pk_keyword");
    urlplus.query_delete("pk_kwd");
    urlplus.query_delete("redirect_log_mongo_id");
    urlplus.query_delete("redirect_mongo_id");
    urlplus.query_delete("rtid");
    urlplus.query_delete("sb_referer_host");
    urlplus.query_delete("ScCid");
    urlplus.query_delete("si");
    urlplus.query_delete("siteurl");
    urlplus.query_delete("s_kwcid");
    urlplus.query_delete("sms_click");
    urlplus.query_delete("sms_source");
    urlplus.query_delete("sms_uph");
    urlplus.query_delete("srsltid");
    urlplus.query_delete("toolid");
    urlplus.query_delete("trk_contact");
    urlplus.query_delete("trk_module");
    urlplus.query_delete("trk_msg");
    urlplus.query_delete("trk_sid");
    urlplus.query_delete("ttclid");
    urlplus.query_delete("twclid");
    urlplus.query_delete("utm_campaign");
    urlplus.query_delete("utm_content");
    urlplus.query_delete("utm_creative_format");
    urlplus.query_delete("utm_id");
    urlplus.query_delete("utm_marketing_tactic");
    urlplus.query_delete("utm_medium");
    urlplus.query_delete("utm_source");
    urlplus.query_delete("utm_source_platform");
    urlplus.query_delete("utm_term");
    urlplus.query_delete("vmcid");
    urlplus.query_delete("wbraid");
    urlplus.query_delete("yclid");
    urlplus.query_delete("zanpid");

    # Writes changes back to the URL and sorts query string parameters alphabetically
    urlplus.write();
    # Remove port number from host header
    uri.set_port();
    uri.write();

    # Remove the proxy header to mitigate the httpoxy vulnerability
    # See https://httpoxy.org/
    unset req.http.proxy;

    # Add X-Forwarded-Proto and Ssl-Offloaded header value based on the protocol
    if(req.http.Ssl-Offloaded == "1") {
        set req.http.X-Forwarded-Proto = "https";
    } elseif (!req.http.Ssl-Offloaded && req.http.X-Forwarded-Proto == "https") {
        set req.http.Ssl-Offloaded = "1";
    } elseif(!req.http.Ssl-Offloaded && !req.http.X-Forwarded-Proto && tls.is_tls()) {
        set req.http.X-Forwarded-Proto = "https";
        set req.http.Ssl-Offloaded = "1";
    } else {
        set req.http.X-Forwarded-Proto = "http";
        set req.http.Ssl-Offloaded = "0";
    }

    # Reduce grace to the configured setting if the backend is healthy
    # In case of an unhealthy backend, the original grace is used
    if (std.healthy(req.backend_hint)) {
        set req.grace = 300s;
    }

    # Intercept purge requests from Magento to perform cache invalidations
    if (req.method == "PURGE") {
        # Only allow clients that match the ACL
        if (client.ip !~ purge) {
            return (synth(405, "Method not allowed"));
        }
        # Perform a regular URL-based purge when X-Magento-Tags is not set
        if (!req.http.X-Magento-Tags-Pattern) {
            return (purge);
        }
        # Remove regex content from X-Magento-Tags-Pattern and keep the actual comma-separated tags
        set req.http.X-Key-Purge = regsuball(req.http.X-Magento-Tags-Pattern, "[\(\)\^\$]", "");
        set req.http.X-Key-Purge = regsuball(req.http.X-Key-Purge, "[,\|]", " ");
        set req.http.X-Key-Purge = regsuball(req.http.X-Key-Purge, "\.\*", "all");
        # Soft purge objects that match the tags
        set req.http.n-purged = ykey.purge_header(req.http.X-Key-Purge, " ", true);
        return (synth(200, "Purged " + req.http.n-purged + " objects"));
    }

    # If the HTTP request method doesn't match one of these, it's probably not a valid HTTP request
    # Send the content to the backend and abandon any notion of HTTP and HTTP caching
    if (req.method != "GET" &&
        req.method != "HEAD" &&
        req.method != "PUT" &&
        req.method != "POST" &&
        req.method != "PATCH" &&
        req.method != "TRACE" &&
        req.method != "OPTIONS" &&
        req.method != "DELETE") {
        return (pipe);
    }

    # We only cache GET and HEAD requests
    if (req.method != "GET" && req.method != "HEAD") {
        return (pass);
    }

    # Bypass health check requests
    if (req.url ~ "^/(pub/)?(health_check.php)$") {
        return (pass);
    }

    # Collapse multiple cookie headers into one
    std.collect(req.http.Cookie, ";");

    # Static files caching
    if (req.url ~ "^/(pub/)?(media|static)/") {
        # If you decide not to store static content in the cache, just uncomment the next line
        #return (pass);

        # If you decide to cache static files, remove cookies
        unset req.http.Cookie;
        # Remove X-Forwarded-Proto to reduce cache variations
        unset req.http.X-Forwarded-Proto;
    }

    # Don't cache the authenticated GraphQL requests
    if (req.url ~ "/graphql" && req.http.Authorization ~ "^Bearer") {
        return (pass);
    }

    return (hash);
}

sub vcl_hash {
    # Create a cache variation for the GraphQL requests that based on the X-Magento-Vary cookie
    if (req.url !~ "/graphql") {
        hash_data(cookieplus.get("X-Magento-Vary"));
    }

    # Store HTTP and HTTPS content separately
    hash_data(req.http.X-Forwarded-Proto);

    if (req.url ~ "/graphql") {
        if (req.http.X-Magento-Cache-Id) {
            hash_data(req.http.X-Magento-Cache-Id);
        } else {
            # if no X-Magento-Cache-Id (which already contains Store and Currency) is not set, use the HTTP headers
            hash_data(req.http.Store);
            hash_data(req.http.Content-Currency);
        }
    }
}

sub vcl_backend_response {
    # Register X-Magento-Tags header with Ykey
    ykey.add_header(beresp.http.X-Magento-Tags, sep=",");
    # Associate every object with the "all" key, for when a full cache purge takes place
    ykey.add_key("all");

    # Serve stale content for three days after object expiration
    # Perform asynchronous revalidation while stale content is served
    set beresp.grace = 3d;

    # All text-based content can be parsed as ESI
    if (beresp.http.content-type ~ "text") {
        set beresp.do_esi = true;
    }

    # Allow GZIP compression on all JavaScript files and all text-based content
    if (urlplus.get_extension() == "js" || beresp.http.content-type ~ "text") {
        set beresp.do_gzip = true;
    }

    # Add debug headers
    if (beresp.http.X-Magento-Debug) {
        set beresp.http.X-Magento-Cache-Control = beresp.http.Cache-Control;
    }

    # Only cache HTTP 200 and HTTP 404 responses
    if (beresp.status != 200 && beresp.status != 404) {
        set beresp.ttl = 120s;
        set beresp.uncacheable = true;
        return (deliver);
    }

    # Don't cache if the request cache ID doesn't match the response cache ID for graphql requests
    if (bereq.url ~ "/graphql" && bereq.http.X-Magento-Cache-Id && bereq.http.X-Magento-Cache-Id != beresp.http.X-Magento-Cache-Id) {
       set beresp.ttl = 120s;
       set beresp.uncacheable = true;
       return (deliver);
    }

    # Remove the Set-Cookie header for cacheable content
    # Only for HTTP GET & HTTP HEAD requests
    if (beresp.ttl > 0s && (bereq.method == "GET" || bereq.method == "HEAD")) {
        unset beresp.http.Set-Cookie;
    }
}

sub vcl_deliver {
    if (obj.uncacheable) {
        set resp.http.X-Magento-Cache-Debug = "UNCACHEABLE";
    } else if (obj.hits) {
        set resp.http.X-Magento-Cache-Debug = "HIT";
    } else {
        set resp.http.X-Magento-Cache-Debug = "MISS";
    }

    # Not letting browser cache non-static files.
    if (resp.http.Cache-Control !~ "private" && req.url !~ "^/(pub/)?(media|static)/") {
        set resp.http.Pragma = "no-cache";
        set resp.http.Expires = "-1";
        set resp.http.Cache-Control = "no-store, no-cache, must-revalidate, max-age=0";
    }

    if (!resp.http.X-Magento-Debug) {
        unset resp.http.X-Magento-Cache-Debug;
        unset resp.http.Age;
    }
    unset resp.http.X-Magento-Debug;
    unset resp.http.X-Magento-Tags;
    unset resp.http.X-Powered-By;
    unset resp.http.Server;
    unset resp.http.X-Varnish;
    unset resp.http.Via;
    unset resp.http.Link;
}
