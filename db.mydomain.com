$TTL    604800
mydomain.com.   IN  SOA ns.mydomain.com. hostmaster.mydomain.com. (
                 10     ; Serial
                 60     ; Refresh
                 60     ; Retry
            2419200     ; Expire
             604800 )   ; Negative Cache TTL
; Nameservers
mydomain.com.      IN      NS      ns.mydomain.com.

; A records for nameservers
ns.mydomain.com.   IN      A       192.168.1.10

; Other A records
