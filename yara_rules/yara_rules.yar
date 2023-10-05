rule HomeworkRule {
    meta: 
        author      = "Rob D'Aveta - rob.daveta@gmail.com"
        description = "Rule to detect activity related to the attack from the homework logs"
        attack_id   = "1234"

    strings:
        $command_and_control_server = "172.31.62.130"
        $chmod_etc_gshadow = /chmod[ ].+[ ](\/etc\/){0,1}(g){0,1}shadow/
        $exploitdb_download = /exploit-db\.com\/download/
        $offsec_exploit_download = /github\.com\/offensive-security\/exploit-database/

    condition:
        any of them
}