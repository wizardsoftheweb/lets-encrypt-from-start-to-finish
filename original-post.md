2017's been a really scary year for the internet. Corporations strong-armed the W3C into [adding black box DRM to the HTML spec](https://www.eff.org/deeplinks/2017/09/open-letter-w3c-director-ceo-team-and-membership). WPA2 was [cracked](https://www.krackattacks.com/). IoT botnets, [while not making much of a splash this year](http://blog.netlab.360.com/iot_reaper-a-rappid-spreading-new-iot-botnet-en/), are now a regular threat. The US Federal Communications Commissions seems to be in [the final stages of regulatory capture](https://www.fcc.gov/document/fcc-takes-action-restore-internet-freedom).

The fight for US net neutrality has been center stage, at least everywhere I look, for the past month. So much so that I almost missed [this very interesting story about Comcast snooping unencrypted traffic](https://web.archive.org/web/20171214121709/http://forums.xfinity.com/t5/Customer-Service/Are-you-aware-Comcast-is-injecting-400-lines-of-JavaScript-into/td-p/3009551). Within a day or two of reading the original post, I stumbled on [this thread illustrating the same problem within Steam](https://www.reddit.com/r/gaming/comments/7ht8do/comcast_has_decided_to_start_injecting_popups/) (apparently [Steam never learned](http://store.steampowered.com/news/19852/)). Apparently [ISPs have been injecting code for years](https://www.infoworld.com/article/2925839/net-neutrality/code-injection-new-low-isps.html). That's not okay.

<!-- MarkdownTOC  depth="3" -->

- [Note](#note)
- [Background](#background)
    - [HTTP vs HTTPS](#httpvshttps)
    - [HSTS](#hsts)
    - [Let's Encrypt](#letsencrypt)
    - [`certbot`](#certbot)
- [Server Setup](#serversetup)
    - [Certbot](#certbot-1)
    - [Let's Encrypt](#letsencrypt-1)
        - [Nginx](#nginx)
        - [Apache](#apache)
    - [Generic SSL Config](#genericsslconfig)
        - [Location](#location)
        - [Specify Allowed TLS Versions](#specifyallowedtlsversions)
        - [Generate a List of Good Ciphers](#generatealistofgoodciphers)
        - [Specify ECDHE Curve](#specifyecdhecurve)
        - [Generate Diffie-Hellman Group](#generatediffie-hellmangroup)
        - [Use Server Cipher Preference](#useservercipherpreference)
        - [OCSP Stapling](#ocspstapling)
        - [SSL Session](#sslsession)
        - [HSTS](#hsts-1)
        - [Prevent Clickjacking](#preventclickjacking)
        - [Block MIME Sniffing](#blockmimesniffing)
        - [Sample](#sample)
- [Getting and Using Certs](#gettingandusingcerts)
    - [Prepare the Site](#preparethesite)
        - [Providing the User Challenge Access](#providingtheuserchallengeaccess)
        - [Include the Challenge Config](#includethechallengeconfig)
    - [Generate the Cert](#generatethecert)
    - [Wiring up the Cert](#wiringupthecert)
        - [Nginx](#nginx-1)
        - [Apache](#apache-1)
    - [Restart the Server](#restarttheserver)
        - [Nginx](#nginx-2)
        - [Apache](#apache-2)
- [Testing with OpenSSL](#testingwithopenssl)
- [Automating Renewals](#automatingrenewals)
    - [Hooks](#hooks)
        - [Nginx](#nginx-3)
        - [Apache](#apache-3)
    - [Scripting a Renewal](#scriptingarenewal)
        - [`at`](#at)
        - [Scheduling the Renewal](#schedulingtherenewal)
- [Final Note](#finalnote)

<!-- /MarkdownTOC -->

## Note

I wrote the majority of the Apache examples with `httpd` in mind, i.e. from a RHEL perspective. If you instead use `apache2`, most of the stuff should still work, albeit in a different location.

## Background

### HTTP vs HTTPS

The primary difference between [HTTP](https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol) and [HTTPS](https://en.wikipedia.org/wiki/HTTPS) is encryption. The former is transmitted in the clear; the latter is encrypted prior to transmission. As web traffic flows through many nodes between source and destination, there are many opportunities for tampering or sniffing. HTTP neither has the ability to prevent attacks like this nor the hindsight to know they occurred. HTTPS defeats tampering and sniffing via [symmetric-key cryptography](https://en.wikipedia.org/wiki/Symmetric-key_algorithm) (assuming, of course, the attacker does not have access to sufficiently superior hardware).

However, HTTPS isn't just for people that need to pass secrets. It adds an extra layer of authenticity, giving your users some confidence they're actually communicating with you. To an extent, it keeps communication and activity private. HTTPS means the parties involved, and (theoretically) only the parties involved, will communicate.

Serving HTTP content is as simple as throwing something on a public address (well, with DNS and all that too, but I'm doing simple here). Serving HTTPS content requires more tooling. The box in question needs a digital identity (a cert) that will be used to establish secure pipelines. While you can technically [issue one yourself](http://www.selfsignedcertificate.com/), the internet usually expects [a third party](https://en.wikipedia.org/wiki/Certificate_authority) to be involved (and by "usually" I mean "self-signed certs are never accepted"). After obtaining digital ID, the content has to be served via encryption libraries (e.g. [the indomitable OpenSSL](https://www.openssl.org/)) and consumed by user agents capable of handling the encrypted tunnels (glossing over some refactoring that inevitably must be done to fix protocol-aware content). Modern webservers and browsers make the entire exchange fairly straightforward.

To make life easier, HTTPS content is usually served with additional HTTP pointers to the secure content, which cover user agents that don't try HTTPS by default. Nine times out of ten that means `http://example.com/page` gets a `301 Moved Permanently` that points to `https://example.com/page` (and I'm not sure what happens the other one time). HTTP and HTTPS are two very different protocols (rather, [application layer](https://en.wikipedia.org/wiki/Application_layer) v.s. [transport layer](https://en.wikipedia.org/wiki/Transport_layer)), so you can't serve HTTPS as HTTP. Instead, you instruct the user to resend the request using HTTPS.

### HSTS

HTTP Strict Transport Security (HSTS) is [a web standard](https://tools.ietf.org/html/rfc6797) that instructs user agents to use strict HTTPS. Its support is [pretty universal](https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security#Browser_support). The HSTS header automatically redirects HTTP traffic to HTTPS, adding another layer of enforcement. If it encounters an invalid HTTPS configuration (e.g. cert errors), HSTS prevents users from accessing the page entirely (e.g. [this intentional error page](https://subdomain.preloaded-hsts.badssl.com/)). It's cached by the browser, not the server, so an attacker can't just remove it from your content and redirect to a spoofed site.

HSTS can make sites a bit more complicated. It's recommended [to cover subdomains](https://blog.qualys.com/securitylabs/2016/03/28/the-importance-of-a-proper-http-strict-transport-security-implementation-on-your-web-server), but that can be complicated on larger sites. Wildcard certs and HSTS can actually [track everything ever](https://github.com/ben174/hsts-cookie), so you have to be aware of what you're loading externally. Finally, attackers aren't the only ones that can break HSTS. If your configuration breaks (e.g. forgot to renew the cert), users are locked out until you fix it.

### Let's Encrypt

From [its homepage](https://letsencrypt.org/),

> Let’s Encrypt is a free, automated, and open Certificate Authority.

No one should have to pay for secure communication. If you feel the same way and can afford it, [please pay it forward](https://letsencrypt.org/donate/).

### `certbot`

[The Electronic Frontier Foundation](https://www.eff.org/) has spearheaded [an amazing tool](https://certbot.eff.org) to set up and deploy Let's Encrypt certs anywhere (technically POSIX only but also technically you can make it work with a virtual machine and some elbow grease).


## Server Setup

I've been using something like [this Gist](https://gist.github.com/cecilemuller/a26737699a7e70a7093d4dc115915de8) for several months; I don't think I actually built my config from that one but it (or [a fork](https://gist.github.com/cecilemuller/a26737699a7e70a7093d4dc115915de8/forks)) was certainly influential in the process.

### Certbot

You can follow distro-specific instructions [via the official docs](https://certbot.eff.org/docs/install.html), or use these generic instructions:

```bash
$ wget https://dl.eff.org/certbot-auto
$ wget -N https://dl.eff.org/certbot-auto.asc
$ gpg2 --recv-key A2CFB51FA275A7286234E7B24D17C995CD9775F2
$ gpg2 --trusted-key 4D17C995CD9775F2 --verify certbot-auto.asc certbot-auto
$ chmod a+x ./certbot-auto
$ sudo mv ./certbot-auto /usr/bin/certbot
```

### Let's Encrypt

This creates a centralized location for challenges. If you're running a single site, it's not as useful. The more sites you have, the more useful it becomes.

I prefer [the `/srv` directory](http://refspecs.linuxfoundation.org/FHS_2.3/fhs-2.3.html#SRVDATAFORSERVICESPROVIDEDBYSYSTEM) over [the `/var` directory](http://refspecs.linuxfoundation.org/FHS_2.3/fhs-2.3.html#THEVARHIERARCHY), YMMV.

```bash
$ sudo groupadd letsencrypt
$ sudo mkdir -p /srv/www/letsencrypt/.well-known/acme-challenge
$ sudo chown :letsencrypt /srv/www/letsencrypt
$ sudo chmod g+rwx /srv/www/letsencrypt
```

We'll also want to save a snippet dropping the webserver here.

#### Nginx

This is just a simple location block.

```
$ cat /etc/nginx/common/letsencrypt.conf

location ^~ /.well-known/acme-challenge/ {
	default_type "text/plain";
	root /srv/www/letsencrypt;
}
```

I've got at least three servers running a variant of this right now.

#### Apache

From [the Let's Encrypt forums](https://community.letsencrypt.org/t/apache-multidomain-webroot/10663/2),

```
Alias /.well-known/acme-challenge/ /srv/www/letsencrypt/.well-known/acme-challenge/
<Directory "/srv/www/letsencrypt/.well-known/acme-challenge/">
    Options None
    AllowOverride None
    ForceType text/plain
    RedirectMatch 404 "^(?!/\.well-known/acme-challenge/[\w-]{43}$)"
</Directory>
```

I have not tested this.

### Generic SSL Config

I'll be using [the Qualsys suggested configuration](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices) to set this up. Most of this stuff is explained elsewhere on the internet. I wanted to grok the whole process, so I wrote it up.

I've included Nginx and Apache config because I support both at work, but I've only tested the Nginx config. Apache confuses me.

#### Location

This creates a single file to hold the common config.

###### Nginx

```bash
$ sudo touch /etc/nginx/common/ssl.conf
```

###### Apache

```bash
$ sudo touch /etc/httpd/common/ssl.conf
```

You'll also need to ensure you've got the right modules installed and running.

```bash
$ which a2enmod && echo "apache2" || echo "httpd"
```

* If you're running `httpd`, edit enable them via `/etc/httpd/conf.modules.d/00-base.conf`.
* If you're running `apache2`, enable them via `a2enmod`.

You'll need these modules:

* `mod_rewrite`
* `mod_ssl`
* `mod_socache_shmcb` for any caching (sessions, stapling)

```bash
$ $(which apachectl && echo apachectl || echo httpd) -M | grep -E "rewrite|ssl|socache"
```

#### Specify Allowed TLS Versions

Qualsys says [`v1.2` is the only secure version](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices#22-use-secure-protocols).

###### Nginx

```
ssl_protocols TLSv1.2;
```

###### Apache

```
SSLProtocol -all +TLSv1.2
```

#### Generate a List of Good Ciphers

You might check [the current list](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices#23-use-secure-cipher-suites) to make sure this is up-to-date. You can also shorten this list; I was curious how it was built.

```bash
$ grep -Fx \
		-f <(cat <<-EOF
			ECDHE-ECDSA-AES128-GCM-SHA256
			ECDHE-ECDSA-AES256-GCM-SHA384
			ECDHE-ECDSA-AES128-SHA
			ECDHE-ECDSA-AES256-SHA
			ECDHE-ECDSA-AES128-SHA256
			ECDHE-ECDSA-AES256-SHA384
			ECDHE-RSA-AES128-GCM-SHA256
			ECDHE-RSA-AES256-GCM-SHA384
			ECDHE-RSA-AES128-SHA
			ECDHE-RSA-AES256-SHA
			ECDHE-RSA-AES128-SHA256
			ECDHE-RSA-AES256-SHA384
			DHE-RSA-AES128-GCM-SHA256
			DHE-RSA-AES256-GCM-SHA384
			DHE-RSA-AES128-SHA
			DHE-RSA-AES256-SHA
			DHE-RSA-AES128-SHA256
			DHE-RSA-AES256-SHA256
			EOF
		) \
		<( openssl ciphers | tr ':' '\n' ) \

ECDHE-RSA-AES256-GCM-SHA384
ECDHE-ECDSA-AES256-GCM-SHA384
ECDHE-RSA-AES256-SHA384
ECDHE-ECDSA-AES256-SHA384
ECDHE-RSA-AES256-SHA
ECDHE-ECDSA-AES256-SHA
DHE-RSA-AES256-GCM-SHA384
DHE-RSA-AES256-SHA256
DHE-RSA-AES256-SHA
ECDHE-RSA-AES128-GCM-SHA256
ECDHE-ECDSA-AES128-GCM-SHA256
ECDHE-RSA-AES128-SHA256
ECDHE-ECDSA-AES128-SHA256
ECDHE-RSA-AES128-SHA
ECDHE-ECDSA-AES128-SHA
DHE-RSA-AES128-GCM-SHA256
DHE-RSA-AES128-SHA256
DHE-RSA-AES128-SHA
```
That's not the order Qualsys uses, and I've yet to figure out a good way to maintain the original order. However, it does show you what you can use.

#### Specify ECDHE Curve

Qualsys suggests using a [specific elliptic curve for ECDHE](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices#26-use-strong-key-exchange).

###### Nginx

```
ssl_protocols secp256r1;
```

###### Apache

```
SSLOpenSSLConfCmd Curves P-256
```

#### Generate Diffie-Hellman Group

Vanilla OpenSSL is susceptible to [Logjam](https://weakdh.org/) (among other things), so you'll want to create a new Diffie-Hellman group.


###### Nginx

To generate,

```bash
$ sudo mkdir -p /etc/nginx/ssl
$ sudo openssl dhparam -out /etc/nginx/ssl/dhparams.pem 2048
```

To use,

```
ssl_dhparam /etc/nginx/ssl/dhparams.pem;
```

###### Apache

To generate,

```bash
$ sudo mkdir -p /etc/httpd/ssl
$ sudo openssl dhparam -out /etc/httpd/ssl/dhparams.pem 2048
```

To use,

```
SSLOpenSSLConfCmd DHParameter "/etc/httpd/ssl/dhparams.pem"
```

#### Use Server Cipher Preference

This will default to the server's cipher order over the client's order.

###### Nginx

```
ssl_prefer_server_ciphers on;
```

###### Apache

```
SSLHonorCipherOrder on
```

#### OCSP Stapling

[OCSP Stapling](https://en.wikipedia.org/wiki/OCSP_stapling) makes things a little bit simpler for Let's Encrypt.

###### Nginx
This config requires [also setting `ssl_trusted_certificate`](http://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_stapling_verify).

```
ssl_stapling on;
ssl_stapling_verify on;
```

###### Apache

Apache doesn't [make it easy](https://httpd.apache.org/docs/trunk/ssl/ssl_howto.html#ocspstapling). Here's [a Stack Exchange thread](https://unix.stackexchange.com/a/394074) that seems to cover the important stuff.

```
SSLUseStapling On
SSLStaplingCache "shmcb:ssl_stapling(32768)"
```

#### SSL Session
Values from [Mozilla's generator](https://mozilla.github.io/server-side-tls/ssl-config-generator/). TLS tickets [present issues](https://wiki.mozilla.org/Security/Server_Side_TLS#TLS_tickets_.28RFC_5077.29), so I've disabled them.

###### Nginx

```
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;
ssl_session_tickets off;
```

###### Apache

Apache again [makes this difficult](https://wiki.apache.org/httpd/SSLSessionCache). It does look like disabling tickets is easy.

```
SSLSessionCache "<some value>"
SSLOpenSSLConfCmd Options -SessionTicket
```

#### HSTS

To make things easier, we'll give the cache a half-life of two years:

![63072000-origin-1](/content/images/2017/12/63072000-origin-1.png)

###### Nginx

```
add_header Strict-Transport-Security "max-age=63072000; includeSubdomains";
```

###### Apache

```
Header always set Strict-Transport-Security "max-age=63072000; includeSubdomains";
```

#### Prevent Clickjacking

Depending on your configuration, you might not want this. This will explicitly prevent anyone from serving your content inside an `iframe`.

###### Nginx

```
add_header X-Frame-Options DENY;
```

###### Apache

```
Header set X-Frame-Options "DENY"
```

#### Block MIME Sniffing

This will prevent [content sniffing](https://en.wikipedia.org/wiki/Content_sniffing).

###### Nginx

```
add_header X-Content-Type-Options nosniff;
```

###### Apache

```
Header set X-Content-Type-Options "nosniff"
```

#### Sample

###### Nginx

```bash
$ cat /etc/nginx/common/ssl.conf

ssl_protocols TLSv1.2;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA256;
ssl_protocols secp256r1;
ssl_prefer_server_ciphers on;

ssl_stapling on;
ssl_stapling_verify on;

ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;
ssl_session_tickets off;

add_header Strict-Transport-Security "max-age=63072000; includeSubdomains";
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
```

###### Apache

I didn't actually build a full Apache file.

## Getting and Using Certs

I'll be using [Mozilla's config generator](https://mozilla.github.io/server-side-tls/ssl-config-generator/) again for simplicity.

### Prepare the Site

Let's assume we start with examples like these:

###### Nginx

```
server {
    listen 80 default_server;
    listen [::]:80 default_server ipv6only=on;

    server_name example.com www.example.com;

    root /srv/www/example.com;
}
```

###### Apache

```
Listen 80
<VirtualHost *:80>
    DocumentRoot "/srv/www/example.com"
    ServerName example.com www.example.com
</VirtualHost>
```

#### Providing the User Challenge Access

The reason we built the group and external folder previously was so that it would be easy to access later. Simply add the website user to the `letsencrypt` group.

```bash
$ sudo usermod -G letsencrypt nginx
# or, if you're being careful
$ sudo usermod -G letsencrypt siteserviceaccount
```

#### Include the Challenge Config

###### Nginx

```
server {
    listen 80 default_server;
    listen [::]:80 default_server ipv6only=on;

    server_name example.com www.example.com;

    include /etc/nginx/common/letsencrypt.conf;

    root /srv/www/example.com;
}
```

###### Apache

```
Listen 80
<VirtualHost *:80>
    DocumentRoot "/srv/www/example.com"
    ServerName example.com www.example.com
    Include /etc/httpd/common/letsencrypt.conf
</VirtualHost>
```

### Generate the Cert

With everything in place, we can finally create a cert. All of this manual configuration was done to give us some flexibility over the final product. We're going to pass `certbot` a ton of options to handle this

* We only want a cert, not an installation
* We're going to agree to [the TOS](https://letsencrypt.org/repository/)
* We're going to register an email for important contacts
* We're going to skip joining [the EFF email list](https://www.eff.org/effector)
* We're going to specify the webroot (i.e. the directory to place the challenges)
* We're going to specify all the domains AND subdomains on the cert

```bash
$ certbot 						\
	certonly 					\
	--agree-tos 				\
	--email your@email.address 	\
	--no-eff-email 				\
	-w /srv/www/letsencrypt 	\
	-d example.com 				\
	-d www.example.com 			\
	-d anotherone.example.com
```

Depending on how things ran, you might have an issue or two to fix. If it worked, you'll get a confirmation notice.

You can verify the files were properly created by checking the Let's Encrypt directory.

```bash
$ cat /etc/letsencrypt/live/example.com/README
This directory contains your keys and certificates.

`privkey.pem`  : the private key for your certificate.
`fullchain.pem`: the certificate file used in most server software.
`chain.pem`    : used for OCSP stapling in Nginx >=1.3.7.
`cert.pem`     : will break many server configurations, and should not be used
                 without reading further documentation (see link below).

We recommend not moving these files. For more information, see the Certbot
User Guide at https://certbot.eff.org/docs/using.html#where-are-my-certificates.
```

### Wiring up the Cert

#### Nginx

We paused with a config like this:

```
server {
    listen 80 default_server;
    listen [::]:80 default_server ipv6only=on;

    server_name example.com www.example.com;

    include /etc/nginx/common/letsencrypt.conf;

    root /srv/www/example.com;
}
```
We can replace it with something like this:
```
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    server_name example.com www.example.com;

    include /etc/nginx/common/letsencrypt.conf;

    return 301 https://$host$request_uri;
}
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    server_name example.com www.example.com;

    include /etc/nginx/common/ssl.conf;

    # Normal cert
    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    # Private key
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
    # OCSP stapling cert
    ssl_trusted_certificate /etc/letsencrypt/live/example.com/chain.pem;

    root /srv/www/example.com;
}
```

#### Apache

We paused with a config like this:

```
Listen 80
<VirtualHost *:80>
    DocumentRoot "/srv/www/example.com"
    ServerName example.com www.example.com
    Include /etc/httpd/common/letsencrypt.conf
</VirtualHost>
```
We can replace it with something like this:
```
Listen 80
Listen 443
<VirtualHost *:80>
    DocumentRoot "/srv/www/example.com"
    ServerName example.com www.example.com
    Include /etc/httpd/common/letsencrypt.conf
    # https://serverfault.com/a/739128/446829
    RewriteEngine On
	RewriteCond %{HTTPS} off
    RewriteCond %{REQUEST_URI} !^/\.well\-known/acme\-challenge/
    RewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]
</VirtualHost>
<VirtualHost *:443>
    DocumentRoot "/srv/www/example.com"
    ServerName example.com www.example.com

    # Include scoped config

    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/example.com/privkey.pem
</VirtualHost>
# Include global config
```

As before, I haven't tested the Apache config. At all. It might fail spectatularly.

### Restart the Server

#### Nginx

```bash
$ sudo nginx -t && sudo systemctl restart nginx || echo "whoops"
```

#### Apache

```bash
$ sudo httpd -t && sudo systemctl restart httpd || echo "whoops"
```

## Testing with OpenSSL

You can quickly verify your settings with `openssl`. If there are any errors and you just restarted the server process, wait a few minutes and try again. The OCSP stapling especially takes more than a few seconds to propagate.

```bash
$ openssl s_client 				\
	-connect example.com:443 	\
	-servername example.com 	\
	-tls1_2						\
	-status
	
CONNECTED(00000003)
depth=2 O = Digital Signature Trust Co., CN = DST Root CA X3
verify return:1
depth=1 C = US, O = Let's Encrypt, CN = Let's Encrypt Authority X3
verify return:1
depth=0 CN = example.com
verify return:1
OCSP response:
======================================
OCSP Response Data:
    OCSP Response Status: successful (0x0)
    Response Type: Basic OCSP Response
    Version: 1 (0x0)
    Responder Id: C = US, O = Let's Encrypt, CN = Let's Encrypt Authority X3
    ...
======================================
---
Certificate chain
 0 s:/CN=example.com
   i:/C=US/O=Let's Encrypt/CN=Let's Encrypt Authority X3
 1 s:/C=US/O=Let's Encrypt/CN=Let's Encrypt Authority X3
   i:/O=Digital Signature Trust Co./CN=DST Root CA X3
---
Server certificate
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
subject=/CN=example.com
issuer=/C=US/O=Let's Encrypt/CN=Let's Encrypt Authority X3
...
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    ...
---
```

To make sure your content is coming through as intended, you can make [actual HTTP request](https://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html). I've illustrated below with my website. Note that there are two newlines to finish the request.

```bash
$ openssl s_client -connect wizardsoftheweb.pro:443 -servername wizardsoftheweb.pro -tls1_2 -status -quiet
depth=2 O = Digital Signature Trust Co., CN = DST Root CA X3
verify return:1
depth=1 C = US, O = Let's Encrypt, CN = Let's Encrypt Authority X3
verify return:1
depth=0 CN = wizardsoftheweb.pro
verify return:1
GET / HTTP/1.1
HOST: wizardsoftheweb.pro

HTTP/1.1 200 OK
Server: nginx/1.10.2
Date: Sun, 17 Dec 2017 03:04:46 GMT
Content-Type: text/html
Content-Length: 722
Last-Modified: Sun, 28 May 2017 11:02:56 GMT
Connection: keep-alive
Strict-Transport-Security: max-age=63072000; includeSubdomains
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Accept-Ranges: bytes

<!DOCTYPE html>
...
```

Along those lines, we can also test the redirect.

```bash
$ telnet wizardsoftheweb.pro 80
Trying 198.199.79.185...
Connected to wizardsoftheweb.pro.
Escape character is '^]'.
GET / HTTP/1.1
HOST: wizardsoftheweb.pro

HTTP/1.1 301 Moved Permanently
Server: nginx/1.10.2
Date: Sun, 17 Dec 2017 03:12:55 GMT
Content-Type: text/html
Content-Length: 185
Connection: keep-alive
Location: https://www.wizardsoftheweb.pro/

<html>
<head><title>301 Moved Permanently</title></head>
<body bgcolor="white">
<center><h1>301 Moved Permanently</h1></center>
<hr><center>nginx/1.10.2</center>
</body>
</html>
```

## Automating Renewals

Now that everything's installed and in place, we've got to think about keeping the cert current. Let's Encrypt certs have [a 90-day lifetime](https://letsencrypt.org/2015/11/09/why-90-days.html), which is substantially shorter than a typical commercial cert. `certbot` is built to handle automated renewals and can update everything in place without any intervention on your part.

If you try running `certbot renew` right now, you'll probably get something like this:

```bash
$ sudo certbot renew
Saving debug log to /var/log/letsencrypt/letsencrypt.log

-------------------------------------------------------------------------------
Processing /etc/letsencrypt/renewal/example.com.conf
-------------------------------------------------------------------------------
Cert not yet due for renewal

-------------------------------------------------------------------------------

The following certs are not due for renewal yet:
  /etc/letsencrypt/live/example.com.pro/fullchain.pem (skipped)
No renewals were attempted.
-------------------------------------------------------------------------------
```

While the cert isn't due for renewal, we can actually test the renewal process like this:

```bash
$ certbot renew --dry-run
Saving debug log to /var/log/letsencrypt/letsencrypt.log

-------------------------------------------------------------------------------
Processing /etc/letsencrypt/renewal/example.com.conf
-------------------------------------------------------------------------------
Cert not due for renewal, but simulating renewal for dry run
Plugins selected: Authenticator webroot, Installer None
Starting new HTTPS connection (1): acme-staging.api.letsencrypt.org
Renewing an existing certificate
Performing the following challenges:
http-01 challenge for example.com
http-01 challenge for www.example.com
Waiting for verification...
Cleaning up challenges
Dry run: skipping deploy hook command

-------------------------------------------------------------------------------
new certificate deployed without reload, fullchain is
/etc/letsencrypt/live/example.com/fullchain.pem
-------------------------------------------------------------------------------

-------------------------------------------------------------------------------
** DRY RUN: simulating 'certbot renew' close to cert expiry
**          (The test certificates below have not been saved.)

Congratulations, all renewals succeeded. The following certs have been renewed:
  /etc/letsencrypt/live/example.com/fullchain.pem (success)
** DRY RUN: simulating 'certbot renew' close to cert expiry
**          (The test certificates above have not been saved.)
-------------------------------------------------------------------------------
```

### Hooks

You might have noticed the `Dry run: skipping deploy hook command` line in the output. `certbot` can run commands or scripts at several stages in its lifecycle. You can either add hooks via flags every time you `renew`, or you can offload them to executable scripts in `/etc/letsencrypt/renewal-hooks`.

For this example, all I'd like to do is restart the server process following successful renewals. Assuming we've got a local script capable of that called `server-reboot`, this should add it to `certbot`'s pipeline.

```bash
$ sudo cp ./server-reboot /var/letsencrypt/renewal-hooks/deploy
$ sudo chmod +x /var/letsencrypt/renewal-hooks/deploy
```

#### Nginx

```bash
#!/bin/bash

nginx -t && systemctl restart nginx
```

#### Apache

```
#!/bin/bash

apachectl -t && systemctl restart apachectl
```

### Scripting a Renewal

The official documentation suggests running an automated renewal task at least twice a day (e.g. [the CentOS instructions](https://certbot.eff.org/#centosrhel7-nginx); scroll down). `certbot` also asks that you run it at a random minute. To make things easier later, let's isolate our renew command:

```bash
$ sudo cat <<EOF > /sbin/certbot-renew-everything
#!/bin/bash

# Create a temporary file for STDERR
ERROR_LOG=$(mktemp)

# Renew, ignoring STDOUT and piping STDERR to the temp file
/usr/bin/certbot renew > /dev/null 2> "$ERROR_LOG"

if [[ -s "$ERROR_LOG" ]]; then
	mail -s "certbot Renewal Issue" your@email.address < "$ERROR_LOG"
fi

rm -rf "$ERROR_LOG"
EOF

$ sudo chmod 'u=rwx,go=' /sbin/certbot-renew-everything
```

Adding extra flags is straightforward. `renew` only exits [with a nonzero code if the renewal failed](https://github.com/certbot/certbot/blob/v0.20.0/docs/using.rst#modifying-the-renewal-configuration-file) (paragraph right above the link), meaning the skipped renewals we saw earlier don't generate any traffic. They do, however, send many things to `STDOUT`, which is enough to trigger `cron`'s mail action. The `quiet` flag suppresses `STDOUT`, so you won't get multiple emails a day letting you know `certbot` did nothing. If you're into that you don't have to use it.

Most of the solutions I've seen for the randomness do some cool stuff with advanced PRNG and then pass the result to `sleep`. There's nothing wrong with `sleep` if [you're pausing tasks that don't actually need to run](http://man7.org/linux/man-pages/man3/sleep.3.html). Anything that kills the thread kills the task.

#### `at`

`at` provides a much better solution because, [via `man at`](http://man7.org/linux/man-pages/man1/at.1p.html),

> The `at` utility shall read commands from standard input and group them together as an `at-job`, to be executed at a later time.

In other words, `at` is a single-execution `cron`. It manages an `at` queue, most likely accessible via `atq`, which means random power failure or accidentally nuking a remote session won't kill the delayed task. Of course that means some setup is required:

```bash
$ sudo yum install -y at
$ sudo pkill -f atd
$ sudo systemctl enable atd
$ sudo systemctl start atd
$ sudo systemctl status atd
● atd.service - Job spooling tools
   Loaded: loaded (/usr/lib/systemd/system/atd.service; enabled; vendor preset: enabled)
   Active: active (running) since Sun 2017-12-17 11:17:15 UTC; 4s ago
 Main PID: 47 (atd)
   CGroup: /system.slice/atd.service
           4747 /usr/sbin/atd -f

Dec 17 11:17:15 examplehost systemd[1]: Started Job spooling tools.
Dec 17 11:17:15 examplehost systemd[1]: Starting Job spooling tools...
```

* `at` is the command itself
* `atd` is the `at` daemon
* `atq` is an alias for listing `at` jobs
* `atrm` is an alias for removing `at` jobs

###### Block Scheduling

The simplest `at` solution triggers a script like this `NUMBER_OF_DAILY_RUNS` times per day.

```bash
#!/bin/bash

TASK_FILE=/sbin/certbot-renew-everything

# This assumes you've got some control over the machine's at queues
AT_QUEUE="z"

# The number of times we want the script to run in 24 hours
NUMBER_OF_DAILY_RUNS=2

# The calculated maximum number of minutes per block
MAX_MINUTES=$(( 60 * 24 / $NUMBER_OF_DAILY_RUNS ))

# Create 7 pseudorandom bytes, output as hex
PRN_HEX=$(openssl rand -hex 7)
# The hex is converted to base 10
PRN_TEN=$(( 16#$PRN_HEX ))
# Finally, PRN_TEN is taken mod MAX_MINUTES to fit the domain
PRN_MIN=$(( $PRN_TEN % $MAX_MINUTES ))

# Only execute if this queue is empty
if [[ -z "$( atq -q $AT_QUEUE )" ]]; then
	at "now +${PRN_MIN} min" -q "$AT_QUEUE" -f "$TASK_FILE"
fi
```

###### Random Scheduling

A slightly more involved `at` script calls both the task and itself.

```bash
#!/bin/bash

# Store original noclobber
ORIGINAL_NOCLOBBER=$( set +o | grep noclobber )
set +o noclobber

# Pull out the PRNG into a function
function openssl_prng {
	MAX=$1
	# Create 7 pseudorandom bytes, output as hex
	PRN_HEX=$(openssl rand -hex 7)
	# The hex is converted to base 10
	PRN_TEN=$(( 16#$PRN_HEX ))
	# Finally, PRN_TEN is taken mod MAX to fit the domain
	PRN_MIN=$(( $PRN_TEN % $MAX ))
	return $PRN_MIN
}

# Path to renew task
TASK_FILE=/sbin/certbot-renew-everything

# This assumes you've got some control over the machine's at queues
SCRIPT_QUEUE="y"
TASK_QUEUE="z"

# A hard cap on run count to account for unpleasant randomness
ABSOLUTE_RUN_COUNT_MAX=10

# The number of minutes in 24 hours
MINUTES_IN_TWENTY_FOUR_HOURS=$(( 24 * 60 ))

# When to schedule the next renew run
TASK_SLEEP_MINS=$( openssl_prng $MINUTES_IN_TWENTY_FOUR_HOURS )
# Delay scheduling the next self run by an arbitrary amount
SCRIPT_SLEEP_MINS=$(( $TASK_SLEEP_MINS + 30 ))

# Directory to hold active files
RUN_DIR=/var/run/certbot-renew
mkdir -p "$RUN_DIR"
# File to store current date and run count
RUN_COUNT_FILE="$RUN_DIR/count"
touch "$RUN_COUNT_FILE"
# Using awk, load the file
# 	* If the dates match, use the loaded run count
#	* If not, reset the count
RUN_COUNT=$( awk '{ if ($1 == strftime("%F")) { print $2; } else { print 0; } }' "$RUN_COUNT_FILE" )

# Get the absolute path to this file
RUN_SCRIPT_PATH_FILE="$RUN_DIR/path"
touch "$RUN_SCRIPT_PATH_FILE"
THIS_SCRIPT=$( [[ -s "$RUN_SCRIPT_PATH_FILE" ]] && cat "$RUN_SCRIPT_PATH_FILE" || readlink -m $0)
rm -rf "$RUN_SCRIPT_PATH_FILE"
if [[ -e "$THIS_SCRIPT" ]]; then
	echo "$THIS_SCRIPT" >| "$RUN_SCRIPT_PATH_FILE"
else
	echo "Unable to find self-reference" | systemd-cat -t certbot-renew-everything
	eval "$ORIGINAL_NOCLOBBER"
	exit 1
fi

# Check that RUN_COUNT is low enough and TASK_QUEUE is empty
if [[ "$RUN_COUNT" -lt "$ABSOLUTE_RUN_COUNT_MAX" ]] && [[ -z "$( atq -q $TASK_QUEUE )" ]]; then
	# Increment RUN_COUNT
	RUN_COUNT=$(( $RUN_COUNT + 1 ))
	# Schedule a renew and run count update
	echo "source $TASK_FILE && (date \"+%F $RUN_COUNT\" >| $RUN_COUNT_FILE)" | at "now +${TASK_SLEEP_MINS} min" -q "$TASK_QUEUE"
fi

# Check that SCRIPT_QUEUE is empty
if [[ -z "$( atq -q $SCRIPT_QUEUE )" ]]; then
	# Schedule a new self run
	at "now +${SCRIPT_SLEEP_MINS} min" -q "$SCRIPT_QUEUE" -f "$THIS_SCRIPT"
fi

# Revert to original noclobber
eval "$ORIGINAL_NOCLOBBER"
```
#### Scheduling the Renewal

With or without `at`, you've got to ensure the task is actually being run.

###### `cron`

```bash
$ sudo crontab -e
```
Add a `MAILTO` that looks like this:

```
MAILTO=your@email.address
```
Add one of the following, depending on how you set it up:
```
0 0,12 * * * /full/path/to/certbot renew --quiet
```
```
0 0,12 * * * /sbin/certbot-renew-everything
```
```
0 0,12 * * * /full/path/to/at/runner
```
If you're not changing the time in the script itself, you probably don't want to use `0 0,12`. This launches the task at `00:00` and `12:00` every day. If launching means `at` assigns a random time, or checks to see if it's running, those times aren't a problem. If you're actually hitting Let's Encrypt every day at that time, that's not a great idea.

###### `systemd`

(Note: my `systemd` knowledge is still pretty rudimentary. I'm using to userspace `cron`. If you see anything I can improve, I'd love to know about it!)

We're going to define a [oneshot unit](https://www.freedesktop.org/software/systemd/man/systemd.service.html#Type=) ([example #2](https://www.freedesktop.org/software/systemd/man/systemd.service.html#Examples)):

```bash
$ sudo cat <<EOF > /etc/systemd/system/certbot-renew.service
[Unit]
Description=Attempts to renew all certbot certs

[Service]
Type=oneshot
ExecStart=/full/path/to/at/runner
# ExecStart=/sbin/certbot-renew-everything
# ExecStart=/full/path/to/certbot renew --quiet
EOF

$ sudo chmod 'ugo=r,u+w' /etc/systemd/system/certbot-renew.service
$ sudo systemctl daemon-reload
$ sudo systemctl enable certbot-renew.service
$ sudo systemctl start certbot-renew.service
$ sudo systemctl status certbot-renew.service

● certbot-renew.service - Attempts to renew all certbot certs
   Loaded: loaded (/etc/systemd/system/certbot-renew.service; static; vendor preset: disabled)
   Active: inactive (dead)

Dec 17 14:50:31 wizardsoftheweb1 systemd[1]: Starting Attempts to renew all certbot certs...
Dec 17 14:50:31 wizardsoftheweb1 systemd[1]: Started Attempts to renew all certbot certs.
```

To run it regularly, we also create [a timer](https://www.freedesktop.org/software/systemd/man/systemd.timer.html):

```bash
$ sudo cat <<EOF > /etc/systemd/system/certbot-renew.timer
[Unit]
Description=Run certbot-renew.service every day at 00:00 and 12:00

[Timer]
OnCalendar=*-*-* 00/12:00
Unit=certbot-renew.service
EOF

$ sudo chmod 'ugo=r,u+w' /etc/systemd/system/certbot-renew.timer
$ sudo systemctl daemon-reload
$ sudo systemctl enable certbot-renew.timer
$ sudo systemctl start certbot-renew.timer
$ sudo systemctl status certbot-renew.timer

● certbot-renew.timer - Run certbot-renew.service every day at 00:00 and 12:00.
   Loaded: loaded (/etc/systemd/system/certbot-renew.timer; static; vendor preset: disabled)
   Active: active (waiting) since Sun 2017-12-17 15:03:21 UTC; 4min 3s ago

Dec 17 15:03:21 wizardsoftheweb1 systemd[1]: Started Run certbot-renew.service every day at 00:00 and 12:00.
Dec 17 15:03:21 wizardsoftheweb1 systemd[1]: Starting Run certbot-renew.service every day at 00:00 and 12:00.

$ sudo systemctl list-timers certbot*

NEXT                         LEFT    LAST PASSED UNIT                ACTIVATES
Mon 2017-12-18 00:00:00 UTC  8h left n/a  n/a    certbot-renew.timer certbot-renew.service

1 timers listed.
Pass --all to see loaded but inactive timers, too.
```

## Final Note

Let's Encrypt is a fantastic service. If you like what they do, i.e. appreciate how accessible they've made secure web traffic, [please donate](https://letsencrypt.org/donate/). [EFF's `certbot`](https://certbot.eff.org/) is what powers my site (and basically anything I work on these days); consider [buying them a beer](https://supporters.eff.org/donate/support-lets-encrypt) (it's really just a donate link but you catch my drift).