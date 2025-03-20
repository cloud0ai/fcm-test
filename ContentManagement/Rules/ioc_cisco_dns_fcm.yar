rule ioc_cisco_dns_fcm {
 meta:
    author = "john.doe@codsec.io"
    description = "Detects DNS requests to malicious domains with Cisco Umbrella1"
    short_description = "Cisco Umbrella alert on DNS Malicous Domains"
    severity = "Medium"
    priority = "Medium"
    status = "Testing"
    created_date = "2023-12-11T17:30:00Z"
    rule_version = "1.1"
    yara_version = "YL2.0"
    data_source = "Firewall events"
    confidence_threshold = "50"
    category = "Traffic"
    subcategory = "Local to Remote"

    events:
        $e.metadata.log_type = "UMBRELLA_DNS"
        $e.metadata.event_type = "NETWORK_DNS"
        
        $e.network.application_protocol = "DNS"
        $e.principal.ip = $i
        not $e.principal.ip in %General_safe_IPs_Whitelist


        $e.network.dns.questions.name = $dns_query
        $e.network.dns.questions.name != ""
        //$e.network.dns.questions.name != ""
//$e.network.dns.questions.name != ""

        $ioc.graph.metadata.product_name = "AGENCY_NAME"
        $ioc.graph.entity.domain.name = $dns_query

        
    match:
        $dns_query over 10m

    outcome:
        $risk_score = max(85)
        $network_dns_questions_name = array_distinct($e.network.dns.questions.name)
        $principal_ip = array_distinct($e.principal.ip)

    condition:
        $e and $ioc
}