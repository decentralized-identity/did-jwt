/* eslint-disable */
// it.skip('not a test', () => {})
module.exports = {
  dir: {
    pass: [
      {
        key: 'ewUp+wQ/DIKUpN8TjaL1DD/R+Ftj5KGzSyV2iKVyoMc=',
        cleartext: 'amVpCvxlvxcIdWMme3n2fOiiNxyhKOhifG3TTm0d+LKfaLqXViqo/tWlvMr/24fyCqKgEfSb9IGDOxbIyChJYQ==',
        jwe: {"protected":"eyJhbGciOiJkaXIiLCJlbmMiOiJYQzIwUCJ9","iv":"ywyadlAepv1mQh6evO92c0HwTcGRKcJ8","ciphertext":"LX2Vu-2cc_XiUK_01JLDioz09CdHUXXbA_dmvdtxHGTzR4dBu4bRzfh118xjNBfgNoKIvS4sSQVUZuVL9Tf3ajutEvMo6DHyATBC3XcGM-pFvFELfgocXA","tag":"j5nSojkD4ePOMGqWmRjXTQ"},
      },
      {
        key: 'c3ZPQai0GsI5MQt4UHyqtN41yBb0D9UDoCZFm5Gtcvc=',
        cleartext: 'C55HcL0HK9eFZ9E1iILGKCJFV/ntMgroJCqB/k6uWTzNPMjf/ct2PvwaCTgXf5gNR9+jgIi8VGBg+0cfJYeJ4A==',
        jwe: {"protected":"eyJhbGciOiJkaXIiLCJlbmMiOiJYQzIwUCJ9","iv":"yOFDM3KZ4KBgY7VG188UtVuJBfPtt-Zh","ciphertext":"imPBhTeM0vyws2CZCed4br1zUyQwPlsEKYy9bBwncEnAU6tmlGOU0voNlF0SxQjEzEGi38H4-ELxum6dCVAiY6kZtE_iu2_k1C5I3JV07m7TKcRpPKtyow","tag":"yo5hVvTgM537oRhIWIMhug"},
      },
      {
        key: 'jBIeDmtRANyUHIUHs7ETPBATKefe7qOmzkvAQ6Gf/ck=',
        cleartext: 'CYSp0rLbtl+5l6Xvg8ObOyPX8gwtU4P+OFEmb9f3R/lPucH17+bWp5aRtJ44tg43talt23R7P4RyELj1qoIgrQ==',
        jwe: {"protected":"eyJhbGciOiJkaXIiLCJlbmMiOiJYQzIwUCJ9","iv":"Pb38qK2JHxjkPd55TLvGi2B-sCcrRPj8","ciphertext":"zaZBahRc-uTLmEYtj7FGSziQ-MCv2aWlxuy9RDsAYP2-S4GyxAh2qeHVhYJFxry5Up2hCPzOhVSFaJ48OKSzWaV4ZWvNJhoV7kB8AUJJ1SLyHXHZV2Cnrw","tag":"7zAX06R3yd-OBeUk3bUoKQ"},
      },
    ],
    fail: [
      {
        key: 'ewUp+wQ/DIKUp6298238923987tj5KGzSyV2iKVyoMc=',
        jwe: {"protected":"eyJhbGciOiJkaXIiLCJlbmMiOiJYQzIwUCJ9","iv":"ywyadlAepv1mQh6evO92c0HwTcGRKcJ8","ciphertext":"LX2Vu-2cc_XiUK_01JLDioz09CdHUXXbA_dmvdtxHGTzR4dBu4bRzfh118xjNBfgNoKIvS4sSQVUZuVL9Tf3ajutEvMo6DHyATBC3XcGM-pFvFELfgocXA","tag":"j5nSojkD4ePOMGqWmRjXTQ"},
      },
      {
        key: 'c3ZPQai0GsI5MQt4UHyqtN41yBb0D9UDoCZFm5Gtcvc=',
        jwe: {"protected":"eyJhbGciOiJkaXIiLCJlbmMiOiJYQzIwUCJ9","iv":"yOFDM3KZ4KBgY7VG188UtVuJBfPtt-Zh","ciphertext":"imPBhTeM0vyws2CZCed4br1zUyQwPlsEKYy9bBwncEnAU6tmlGOU0voNlF0SxQjEzEGi38H4-ELxum6dCVAiY6kZtE_iu2_k1C5I3JV07m7TKcRpPKtyow","tag":"yonogo92M537oRhIWIMhug"},
      },
      {
        key: 'jBIeDmtRANyUHIUHs7ETPBATKefe7qOmzkvAQ6Gf/ck=',
        jwe: {"protected":"eyJhbGciOiJkaXIiLCJlbmMiOiJYQzIwUCJ9","iv":"Pb38qK2JHxjkPd55TLvGi2B-sCcrRPj8","ciphertext":"zaZBahRc-uTLmEYtj7FGSziQ-MCv2aWlxuy9RDsAYP2-S4GyxAh2qeHVhYJFxry5Up2hCPzOhVSFaJ48OKSzWaV4ZWvNJhoV7kB8AUJJ1SLyHXHZV2Cnrw","tag":"8zAX06R3yd-OBeUk3bUoKQ"},
      },
    ],
    invalid: [
      {
        jwe: {"protected":"eyJhbGciOiJkaXIiLCJlbmMiOiJYQzIwUCJ9","ciphertext":"LX2Vu-2cc_XiUK_01JLDioz09CdHUXXbA_dmvdtxHGTzR4dBu4bRzfh118xjNBfgNoKIvS4sSQVUZuVL9Tf3ajutEvMo6DHyATBC3XcGM-pFvFELfgocXA"},
      },
      {
        jwe: {"protected":"ey9372fleiJkaXIiLCJlbmMiOiJYQzIwUCJ9","iv":"yOFDM3KZ4KBgY7VG188UtVuJBfPtt-Zh","tag":"yo5hVvTgM537oRhIWIMhug"},
      },
      {
        jwe: {"protected":"eyJhbGciOiJkaXIiLCJlbmMiOiJYQzIwUCJ9","ciphertext":"zaZBahRc-uTLmEYtj7FGSziQ-MCv2aWlxuy9RDsAYP2-S4GyxAh2qeHVhYJFxry5Up2hCPzOhVSFaJ48OKSzWaV4ZWvNJhoV7kB8AUJJ1SLyHXHZV2Cnrw"},
      },
    ]
  },
  x25519: {
    pass: [
      {
        key: '8BOpj5rludUZ2/Q/jssQDqEAWODs/iYWhIa1XZuL7EA=',
        cleartext: '/GOQlvtSg2V6m9L1IfjPpoyunkmjtvzZX5/gh+lo847Ys3oP+1wd0NmAsCGHiSTB58aAx6PG1+Vi4sXUtRP4kw==',
        jwe: {"protected":"eyJlbmMiOiJYQzIwUCIsInRhZyI6IndPY0FhZTBHUzRPOS0wa3RkYnRDYmciLCJpdiI6IkdkblM4cUNPMFJmbU1hblV0TzJuZ095UHUzYVhSVFhlIiwiZXBrIjp7Imt0eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJmamptXzVrTjRITjBOOUpnRjRZZTFPY2NicmNqdGMwT1NiNXZvbEV4UmpBIn19","recipients":[{"header":{"alg":"ECDH-ES+XC20PKW"},"encrypted_key":"4Q3gQ8U0FN7F19HDx2Y-d3XhSrWjfUJxAfTHDE2k8Qo"}],"iv":"VI7kbLVnMe39GkVXnkol5nmFJRHZjDCI","ciphertext":"Bc8xi6B0VM7RH6Q7tBzZE2nAF_x5Xp3tI--knuVb0TFIv4gaIVm4AoH62_KjfDiE2RINhQA0TBu6mSnzSVfU0CsZjJHqo9wPrLa0NMUZwks1Q9EgVUTwyQ","tag":"d5D-NeG5Y5tgdM5BQsjhSA"},
      },
      {
        key: 'eDNWP28pqd0ENqDLX63rHlMlxLCn6HMGI9If4O5R9kc=',
        cleartext: 'ipfSZEdQWP2H0/H2k15KFkzEDx0Qq3oyMTxySNCkNt7aSEVaBKxACpJsE6akTTZUZAowtcXNcnIbCglYFbHhcA==',
        jwe: {"protected":"eyJlbmMiOiJYQzIwUCIsInRhZyI6InRfQTVVdTVaaHduZDBxX2hMdzUycXciLCJpdiI6IndVcWxJazloY1JXQ3NIMHZvSlN2aVpGT1NwcnBtM3hiIiwiZXBrIjp7Imt0eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJ3M09udXgtNVRCUWEwVENZOHI3THlScHpQMnJkMzNsX1VveUhYcktfakdZIn19","recipients":[{"header":{"alg":"ECDH-ES+XC20PKW"},"encrypted_key":"7-vOqMDMStkVrm4GVWueZNgSGOaBDyni5Eg1efivsto"}],"iv":"ahAxCFOYSK26KGoYztDPYv5HJjPPSXVs","ciphertext":"czxhktlX2W-jdxZdcWpQ1KZnwmstruJAjCBYXnhoVb3vB2IxohhQZlYNDpPZr7nJUcR1Tr6k69ZTa1pw1SMI-kljb7F_YUU7BkEpW9xKGphLi7bZJv4ezw","tag":"nIEkGfomHrefYPilik8M1g"},
      },
      {
        key: 'yDNXAL16cugHbccMOtGZpTsv+45Tvji6z45+YydaV3Q=',
        cleartext: '/Ec1pqVhyeyEd2knzRGorg2A1PuQtVrA8KirCMg3msOH7CUGzYen0a1ShxVlIh4QB9qV0PCGZpwZaNkefajjLw==',
        jwe: {"protected":"eyJlbmMiOiJYQzIwUCIsInRhZyI6IlJ0emVOa0VBRVV0UXYzeGJGUzJFN3ciLCJpdiI6IkVBSlVZZ0N4T2pJUkp0dm12R21sdDNGdGxFSWswZ3JkIiwiZXBrIjp7Imt0eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJsMUVTM0E1cGZadjVwQnFqS3BmQzZhUXVqUjlwRmVQNnVqYWxVdEhOTEh3In19","recipients":[{"header":{"alg":"ECDH-ES+XC20PKW"},"encrypted_key":"l27ClhqCGF_aVxg0j3oGgJ8IqUlUyDIbeAzzQwe-yIc"}],"iv":"4sTe21wDiF6QcXeaMRUpnhwqQ3T17sW0","ciphertext":"5Fi2R3yHTdOWVjfws5WUXxJGhvAgHZuAClOwN4JFASUFi25_CYUe16Llt-EoE-17Zaik0anRY5KPi0QHtyhv_LgyRTEs5x-w_ODRj_Su2A0l5p9qSKZ3oQ","tag":"4wdx5B5be0KwFtvlOIu4pQ"},
      },
      {
        key: '4DxssvyRy2MTtjQSuQGiADBkc7LLvk9+usEq2l7qvXU=',
        cleartext: '1tHl6HEhJ1jcZIqCUaDMtdwvTCD8JCcDaP5gWf7B72v4hz6/T9kckXg+GywihTpX6IJztJnFz+Mg8+5kCC56TQ==',
        jwe: {"protected":"eyJlbmMiOiJYQzIwUCJ9","recipients":[{"header":{"alg":"ECDH-ES+XC20PKW","tag":"fH6nMnuRhiwQU2GJ4WjIPA","iv":"lyHZCXk5n-10N6yshzU6lEMyVLR0h9EY","epk":{"kty":"EC","crv":"P-256","x":"2mH373XQ_4IolX_FHzz1sztPs3UwwrP9Bm0D22gy4-U","y":"l8Yg3yTOOqhI9C5qNJhBqfJD9b0eacJZE0-pLCqImag"}},"encrypted_key":"sRAp3GM1vcOs-xQdCEb1OAl6WJxn0hJThRVUfkkW7es"},{"header":{"alg":"ECDH-ES+XC20PKW","tag":"tMK8ojOBHlzvATpzPwVqtQ","iv":"eMtFNTA1nKVgdYiEjWte3aZ-yto3Pp0g","epk":{"kty":"OKP","crv":"X25519","x":"6B5sqfpzjPedAPYpzMGeq6jc3w__GL_EI4dnl9u0ES0"}},"encrypted_key":"EL331vcSsYSDCt4rhLo009bxhCq9vmy07UFf31Ez9mk"}],"iv":"fgrzpDg-3TCKuNC5DMa1pwssyweKJ4Jo","ciphertext":"Kc3J_Z6l8wakQphIa7aO-9y-yvU276aukH-7V18vnT5_H3Y_XNjZlLen_Lxcy7NCq7zuiHjsGl0I3r6ihpdis6aFFQTFYfuTuNJOKO6k8uXU2AQ-KnTazg","tag":"9CF_koFccgK6w9WZho_9eQ"},
      },
      {
        key: 'eCZs/KUhcili+VrQkok1vCkjaw0+r1JJXQhQCnoHtkk=',
        cleartext: 'HTl5rnLkGEVLW8nrdRGjt/ZN96NFA66uqcaO0G4tongh84M1ksnaN9gZ3oQOfy5drbHyGrM7XeEvOcJklGL7nQ==',
        jwe: {"protected":"eyJlbmMiOiJYQzIwUCJ9","recipients":[{"header":{"alg":"ECDH-ES+XC20PKW","tag":"zuxjNSj6X8LkQzDLegzLvw","iv":"Hy5DT4lsdvv0iPnMtgHtkMltMwtR31xm","epk":{"kty":"EC","crv":"P-256","x":"1hG9lIaJbU4JdROv9kTqwWlQhv7EXig8_StyPpfFMhc","y":"wMsWgLZb0ku_hV5OCnj-C51Cn-aV1bpQ1u6Vgj_14JM"}},"encrypted_key":"VgFu-NMEAQ_2bptIelBM5VbNAxzLzngxC6Pi2jxPK-Y"},{"header":{"alg":"ECDH-ES+XC20PKW","tag":"z5YQCCuq0oZtK7RPC3qiFA","iv":"3ylwlloMwFNsLVl3cM4hdrSgj24qVhhN","epk":{"kty":"OKP","crv":"X25519","x":"t0PRwJRI6bTsiw7cwc1hR_6vMPRniEa_mty_dbb5DQQ"}},"encrypted_key":"9TVu8QXnqrc-NipEq0L4eKmETxuMkTEbjI-5lwcFf34"}],"iv":"ZwIHYtA4SqOWVeVamjnpwgWb0x3y7AR-","ciphertext":"v-Ncv3AwgfbjARTMgRjxQVIFOxPc93vNGoEXPuD5Pn5VzEZBLxfEFUj2AYDhmy6CqDtEDcj0feyTNsIYvPxCbWrkQPh0l9ZA7OqPJwkQaQPQToVo0RuRdQ","tag":"A_ys0VFAn4I7LBaeVnxVDw"},
      },
      {
        key: 'YKhFVwQ4p/qHopd8on4nK9lD2XkxHcL8gSoVoVcCa2g=',
        cleartext: '5weKneEgoKXOtp0b3EXXU+Srp6+eb/p3stdvPNMWVD/aGY0YXXISKgaw6bspOzQrzoEP7BXkw6IGsvGM8UxJDQ==',
        jwe: {"protected":"eyJlbmMiOiJYQzIwUCJ9","recipients":[{"header":{"alg":"ECDH-ES+XC20PKW","tag":"zHB0xtGc2Txn_A3xSvyxDg","iv":"LDNjEkDVLpKlezIwGM9P449albGm_rqJ","epk":{"kty":"EC","crv":"P-256","x":"bnX5we_DU3Og_Y2G-nH68dtu0MwQeIzAkuvX_XSgHjo","y":"PKaJjGBPUnFfF-IY-5pvkcIR_wduwU7nXkkBxoQ-GVU"}},"encrypted_key":"XLHmUDaNchfQA4Z90TdDbcT8AxIxKa6E2LCu4I9_DhI"},{"header":{"alg":"ECDH-ES+XC20PKW","tag":"JJYTamBiDaYPbBL4bD6N7A","iv":"wECGWOn8YTnu1z023Ln-mTBnVUdAHi32","epk":{"kty":"OKP","crv":"X25519","x":"dVck85fItGOaGcbyf_oawbHF-HEhN-I-JGA2w42zAHA"}},"encrypted_key":"JsTju0Ir20kEbzHZ0L6EM6baaHAILKRtf4nyBkmYw6M"}],"iv":"g-qIusY6Al4y6K59tmfLh_cF6QwYUyFc","ciphertext":"lTEVzjD9wCebhBuZtrvow_n73xOvzqmuNRrg2KCFOtb_UQ3Xs-dyEt4LSJ4fg9NzPgP3mUWPoMTlcPEuJvnXkkL82H1XhN5YNQ2rQ8_czCDnH-YOfLEcVg","tag":"OS6vH593hXArb2JevDf1pw"},
      },
      {
        key: '+Egu1APNlDqx3YHm1LAsAHeEQi7kCUvhIXunTMpuplQ=',
        cleartext: 'i1WprsPZJy9VP2xiqbyHIQ3q0hOdleHb+e7wlV0u9e/+lzO4IYue0NqBcsrPfnF9EVqQkEpi2maC5ym79H4k4w==',
        jwe: {"protected":"eyJlbmMiOiJYQzIwUCJ9","recipients":[{"header":{"alg":"ECDH-ES+A256KW","epk":{"kty":"OKP","crv":"X25519","x":"2s6Xfe4ignhNvVHVn3s25FO4xBNTk170ZqqllhHHBVQ"}},"encrypted_key":"OHFmMeOC068rgtG_H6NRBvXh-n__bynU_lkL7xMo6hIPGRTW4yNmVA"},{"header":{"alg":"ECDH-ES+XC20PKW","tag":"oLF5ceVwDl11UMiNYIbnJw","iv":"0__i0CcUPS_R_FOQ33hZJqAtxfsfouHj","epk":{"kty":"OKP","crv":"X25519","x":"fcVzcQ3-lO-hmpDtLX_1N7Z1UP31nNCqjEz3SU23zUU"}},"encrypted_key":"PBYJSfnq2gunqyc3goI-vSCwF5bMBHvenvxs8q8ntsA"}],"iv":"vw-eDC1N1KQZrAyTXsCh8bI4Xul2Ap0g","ciphertext":"X9Qp6fnJIpcxbsKQete7nioEFC4sC9d0gS7SH4TDeSlSlSqT9ln3UP6x2hmjz-gn5hg5PEUFaIUkETNuBSyMzHyUpE_Lx5iNAzuRnstfpQ_ZG6hka93Mbw","tag":"9FQnp03c5Us_d1OdPYM7hA"},
      },
      {
        key: 'MCFWVpCL17Y6+Ck8mVhlHv0ezly3SWDEya4DS/4zU14=',
        cleartext: 'q3kCxeF6O/OSCD2R2UjkhS+DMjCN09QPchTK91LOEk5w2HQEJ+Ewo1BpkEYAuRE2CDfcMp4hIYIKc+n88BDALA==',
        jwe: {"protected":"eyJlbmMiOiJYQzIwUCJ9","recipients":[{"header":{"alg":"ECDH-ES+A256KW","epk":{"kty":"OKP","crv":"X25519","x":"h6HwUrtHy0gc7KA5PSrRYtIIJxr4V3L2b0lxhWwLhUo"}},"encrypted_key":"21iyqdWq11QvnngzFHj3wkkIRVOK6rjsdFvXJFH0kMKc8FMA4BXOOg"},{"header":{"alg":"ECDH-ES+XC20PKW","tag":"TGlpNP9uMvW-y6Uc1jXfZg","iv":"szLQC8qOTAcTVbE_QCljXMaC8CmJX3T7","epk":{"kty":"OKP","crv":"X25519","x":"2rxr9f5MTxxTkmyWVGNnSX4coM3MvJguCRsQCrxt9w4"}},"encrypted_key":"ndhYa5ZyPr-X9FAeXLQladjmlZirzkmmHCm5rGr98s8"}],"iv":"Msj-fX46TRocNzhGkzL81wKhfDb9qHeg","ciphertext":"tcFKEWxhz-Q-nsnJppYqmFC5R0VT8fdNR0vJzUynlx--_3KDFIuDUdf0lwuwycbYXrEw94EyxfVZb3tkOADHXNaIC0njlB07_D7__eyK0N5bD88TXSe4lA","tag":"GNnsfuK6-OYVwVc5N0jyHg"},
      },
      {
        key: 'KHJWEr94Z1qgaCCbsKu/oCxb07LR/ufntkr1Lu0stWU=',
        cleartext: '2+YQ5xghWN7RL1BUPHgv39BJRynuZ2+KaiMRsBlnvZzjJclMYSY67SneTmysv3X3yP/DEDkZH2TVPFcHrJRYGg==',
        jwe: {"protected":"eyJlbmMiOiJYQzIwUCJ9","recipients":[{"header":{"alg":"ECDH-ES+A256KW","epk":{"kty":"OKP","crv":"X25519","x":"e7nXXNUZHQQd1lPTK0bzXWteGZGRg2cr73RsaKr2Lyo"}},"encrypted_key":"OASoE721beho7x6dGXKj6LL9NR9z7OI12ZaisNHV3b6EyJjxbWIGeg"},{"header":{"alg":"ECDH-ES+XC20PKW","tag":"bdMaXGwUwNX-obqn7eqO3g","iv":"RzCIyIO4JJbLo544aqpFbIeH7pq1BIR3","epk":{"kty":"OKP","crv":"X25519","x":"lVudXos0kqGtiGpgYj7W_CoWnlKAR5WiNeB_yHZhSS8"}},"encrypted_key":"iTxnM7J8iJQHash-un_EMElCjPEpVcXu0BVeKFLjJRM"}],"iv":"EeBBbmkL5OvvGbuqqiPVZWUhKKJ2L4Pc","ciphertext":"3ODDtCTQKlX6k0CKOBEE0LsbdUreF7ZeeIj27_pmyZ6uYTKikePR1N24ozdO2oGIGuvC-e9aNMLD8lJmfIbQrCzO6DD-c0AB3xULUF-z92EtI9XaGp08uA","tag":"g0IWefR0xt-ubzkUJ2Ufeg"},
      },
    ],
    fail: [
      {
        key: '3A4drc5/C39Mp5A1PgM6rKpor739xJoUk1SZRo7eOiY=',
        cleartext: '4gINQMEs9Qg5H9nqZvwtwSb37HmtbhGCcFOZ2P2mtJU3WzIDnQeiKAaHCNQczvnqThbF66YNwx2vT1MetcotPQ==',
        jwe: {"protected":"eyJlbmMiOiJYQzIwUCIsInRhZyI6Imo5cy10dWthZGFSTWZ0MmV1bDBZc2ciLCJpdiI6InhTY29yMUQxemVSOS13dHk5X3RPb2hOUTIwWTU3SUVhIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiLXhUVU0yazgtanN1REFLNXBXdWI0QzN5VmQzdm9INzc4NHZTUWMxdUdtNCIsInkiOiJUY1JmbUlmMzAyQjlqc0JKVmJxYldfTUQzSXgxdjZLaWhUVFN1ZGFiZW9ZIn19","recipients":[{"header":{"alg":"ECDH-ES+XC20PKW"},"encrypted_key":"ufEVimxuEjOSL3xxosddCnxAycHyEM6YvZnpnBNcFdU"}],"iv":"KH-z-rAni0OXCwZdEsBdr70Nb9ynB-L0","ciphertext":"GzKj8F4eCBedNXdVQsdPAGRfeTQ84GR-VwA6wQ3oVD4GgD9dXPGVkWTulYPiHCFTR-8P1SCAlxHal0xxONTU5FYz5x3cp4AArhlu5mHjBRcULSx_73uARA","tag":"P5CBxBsYl91xUU1WCUebUg"},
      },
      {
        key: 'Y4CcBWKGI1bB1gXLZZGAzcgI6A67YDwwRutGWOkLAK8=',
        cleartext: 'bn573RKyGwNSyVzZA5nAOqDSP4j8C4aCjdyGQbgIUyhKLsdH7j+SZW/wUZfzOgttTewtYgL1XiifSqJ3ngqg5Q==',
        jwe: {"protected":"eyJlbmMiOiJYQzIwUCIsInRhZyI6ImpTdDRnT2RFc3prbHd1ZkZXX0dDQVEiLCJpdiI6IlFVNHBlTTZNT2R5R2c5ZThNVFFPWnl0Wl9nUHJaMk1NIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiSk5KVG9XWE02cWh0NTktRXJ0dURrYUdVQWpmdWRyNlo2MUFnWkN1ZVFvNCIsInkiOiJLZk9JaDlIdFJKdWFGM3l1S0hkUklwUU5GTk9nbThpMHF1ZzlPUTEyUTR3In19","recipients":[{"header":{"alg":"ECDH-ES+XC20PKW"},"encrypted_key":"mV0ROPhCkbkl6kpqxrJHwtUmp1ag1fX2_Cm1EBVMkH8"}],"iv":"KvOPK3HF_zQ76CrrGsb6Fsf-uz5f2wpw","ciphertext":"tsAJjW2qLZ8ZjwH-rLZKu-skQMz04-WGWYDstN_LwFHd7JRzUj4hSjf_rTS-2U9xUZBH2WkMWT5uRbgiHDz5K5tQUi84ZIILhCBA2hr60qcW-U-m0z6sqA","tag":"6k5ye5rlmaRTOH4sWOWHBA"},
      },
      {
        key: 'uUg6Ufa0ZYYowu+IRMak5rCo64zp9Lg0yiXTv5LgCKk=',
        cleartext: '/RbzIj+Mp/CDm/O+ynz9F3pjZh8vZG4g9MuKFGPCC1lj29N2FqPe/vHOewSfEHc9wLEspNdU1nRmqGWYMq42rg==',
        jwe: {"protected":"eyJlbmMiOiJYQzIwUCIsInRhZyI6IndJaGpzcmdEUGp5X3h3b3ByUDBEeUEiLCJpdiI6IjFxWEJzdDRMS1NWcHhaMHF1VkRxcjNvUzY2SkZLeGREIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiRS1MSGFoQlVjSERzNDFiaXpQT2hwWHVrWmd4M00xSWdFQXFRNkV2dW1mcyIsInkiOiJlYkNoWklPUGlLM0kxTnlCZEN3bmdVSTZxRHptSUxLUlN0RkRIUFRSU1Q4In19","recipients":[{"header":{"alg":"ECDH-ES+XC20PKW"},"encrypted_key":"H6hUldKGflwKIKwgucoJBTEVemkOEJaM5BUH-M0cLQk"}],"iv":"d-qf4TZIGY_CRr5uhqjN0H11-qdppk8l","ciphertext":"FMT52nFNQUE7GForruf__VStmxKYvuwufkm8C6nyk7iiHF_QpCvlxDY0e47IEZkIKag5f4X2PEvNqh-uOkDz5TGsIFkL-aOk12j-AUFv6bCRZsCQZ0M-Gw","tag":"voS431umtRfWH0gmHJWrGA"},
      },
      {
        key: 'iK33APP9aA6I69dasmF0rhdnyDS/G9L2BmQrPdQOHEE=',
        cleartext: 'KH5Ur3uMZE7lhMxe46e8AEUMQbJ8GpKbfwZ46I1rAHtDbBu70Mh/lCYpk1HzRQmloUJZpGmxmtDxmop7sXfx8A==',
        jwe: {"protected":"eyJlbmMiOiJYQzIwUCIsImVwayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ4IjoiaEd3NldscjFJVzE1ZjQyVDVlUGp5WWtJd2stT0VOUFRVMmdrSHBSN1F6cyJ9fQ","recipients":[{"header":{"alg":"ECDH-ES+A256KW"},"encrypted_key":"_xDecY9QBM9Hy4wSCBrqomLk1iViBKnWOHgyQTvitWRbvxPPCsDmmQ"}],"iv":"HT0ou7YvuxoUbQrDKz7-ZhJh2sMH-oH3","ciphertext":"KhmVw1-IfJvaUfqRPy8K4o_-m5Hvad4XOJGwz3S5YpxZNcW1y5PAr8wB3fpx5zmyK4DW0yMF-PGNj5kE5mk6WeeeoZv19QeOufaR5Pr5WY78Ul9OqycnMg","tag":"VpzJHJGEzQErVC7WWoIRxQ"},
      },
      {
        key: 'SCuKo9m6RVkqh+I3NMD8fJkqeMttJuMUW9wUOHkVk3I=',
        cleartext: 'n8Ra/8Ab7i/mdGUhfENLGbWSolgHN8vTOqcd+CommbomwVSlfXsY3FNHIzL23QExfREVG3BmAFSPC7U6W9Q5EQ==',
        jwe: {"protected":"eyJlbmMiOiJYQzIwUCIsImVwayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ4IjoiQ3ExaGU0MzJDTVY3enhoLVd4WE1LUkJiWlpiV3J2UTdZOGV3WXMzOVFCNCJ9fQ","recipients":[{"header":{"alg":"ECDH-ES+A256KW"},"encrypted_key":"ts9HUWBgesW1npI3Sj5dsZkcOsjTrW2c5UVruUN5eqAgQX29QJvpKw"}],"iv":"QQ7yoMGme-Nieiv18ADKmB_ckOnTsZ1x","ciphertext":"2IGWszPbwbpf0eLDoUVy2X9eHw0dCNiQMwS5b7sVcL9CbuLRcE3mTe4b60Ux7unwIf174EZ4ZgXTE2aMZHEKW1Az-5Cz03yt7QrWZTyoTQz98BviWtVhww","tag":"uKtJArMp1T_4YzFjYXKEiA"},
      },
      {
        key: 'YMhqFQ3i9P1WXA7kPfg9G+yYPH897ao+vj4Xp6vD+XA=',
        cleartext: 'NtOHYk4fqBjTKP7/dIXULV3ZU4hTHZftrsQIhvkEeotR54Q2Hi13SSbAHQc/V6/p5wbPB38f3WafLzzQMBhNCg==',
        jwe: {"protected":"eyJlbmMiOiJYQzIwUCIsImVwayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ4IjoiTGZGMFNmdzVXTUNmd0xxVDM2WVpmUXgyZjFJR2x6R0RRQTNGdjNGaTdETSJ9fQ","recipients":[{"header":{"alg":"ECDH-ES+A256KW"},"encrypted_key":"VxCxFVDXQv9eKZP6B_I_v1gyRZqnjJ3u0zKOws0FoKsFspl-NQ-Scw"}],"iv":"7UHZXc01BIfW6QK4g2hQ8gCwj9b26k7F","ciphertext":"Nq6x2A6Bcu5hD6qD4EeEYKtcvlY11pIlQkfeUCCxyKuGgWfSHb4I3MqSN5fdCts3eGyNBaflfacS136--av5VSynBFVJbC_5AYJUrAxeGpaotc5nGxjLrA","tag":"XuU1rzfvst13I6hJjZEFZA"},
      },
    ],
    invalid: [
      {
        jwe: {"protected":"eyJlbmMiOiJYQzIwUCJ9","iv":"4wlzzbWHDToIqHwqiuuOSj-AbFOSjU-k","ciphertext":"vTx44FaUkDCbIn2CmVyZ94BobjJ8YuzAfr2ENCwtpqD6kBjFFm7eURsqAQKIM_HlquPHKbqoc7ePGVVm5Io4Mkv8J368jvot-hK1CenwfTqAXqt-MjEetw","tag":"xRelvbSksojh5bN5_uQu2A"},
      },
      {
        jwe: {"protected":"eyJlbmMiOiJYQzIwUCJ9","recipients":[],"iv":"4wlzzbWHDToIqHwqiuuOSj-AbFOSjU-k","ciphertext":"vTx44FaUkDCbIn2CmVyZ94BobjJ8YuzAfr2ENCwtpqD6kBjFFm7eURsqAQKIM_HlquPHKbqoc7ePGVVm5Io4Mkv8J368jvot-hK1CenwfTqAXqt-MjEetw","tag":"xRelvbSksojh5bN5_uQu2A"},
      },
      {
        jwe: {"protected":"eyJlbmMiOiJYQzIwUCJ9","recipients":[{"encrypted_key":"sRAp3GM1vcOs-xQdCEb1OAl6WJxn0hJThRVUfkkW7es"},{"header":{"alg":"ECDH-ES+XC20PKW","tag":"tMK8ojOBHlzvATpzPwVqtQ","iv":"eMtFNTA1nKVgdYiEjWte3aZ-yto3Pp0g","epk":{"kty":"OKP","crv":"X25519","x":"6B5sqfpzjPedAPYpzMGeq6jc3w__GL_EI4dnl9u0ES0"}},"encrypted_key":"EL331vcSsYSDCt4rhLo009bxhCq9vmy07UFf31Ez9mk"}],"iv":"fgrzpDg-3TCKuNC5DMa1pwssyweKJ4Jo","ciphertext":"Kc3J_Z6l8wakQphIa7aO-9y-yvU276aukH-7V18vnT5_H3Y_XNjZlLen_Lxcy7NCq7zuiHjsGl0I3r6ihpdis6aFFQTFYfuTuNJOKO6k8uXU2AQ-KnTazg","tag":"9CF_koFccgK6w9WZho_9eQ"},
      },
      {
        jwe: {"protected":"eyJlbmMiOiJYQzIwUCJ9","recipients":[{"header":{"alg":"ECDH-ES+XC20PKW","tag":"fH6nMnuRhiwQU2GJ4WjIPA","epk":{"kty":"EC","crv":"P-256","x":"2mH373XQ_4IolX_FHzz1sztPs3UwwrP9Bm0D22gy4-U","y":"l8Yg3yTOOqhI9C5qNJhBqfJD9b0eacJZE0-pLCqImag"}},"encrypted_key":"sRAp3GM1vcOs-xQdCEb1OAl6WJxn0hJThRVUfkkW7es"},{"header":{"alg":"ECDH-ES+XC20PKW","tag":"tMK8ojOBHlzvATpzPwVqtQ","iv":"eMtFNTA1nKVgdYiEjWte3aZ-yto3Pp0g","epk":{"kty":"OKP","crv":"X25519","x":"6B5sqfpzjPedAPYpzMGeq6jc3w__GL_EI4dnl9u0ES0"}},"encrypted_key":"EL331vcSsYSDCt4rhLo009bxhCq9vmy07UFf31Ez9mk"}],"iv":"fgrzpDg-3TCKuNC5DMa1pwssyweKJ4Jo","ciphertext":"Kc3J_Z6l8wakQphIa7aO-9y-yvU276aukH-7V18vnT5_H3Y_XNjZlLen_Lxcy7NCq7zuiHjsGl0I3r6ihpdis6aFFQTFYfuTuNJOKO6k8uXU2AQ-KnTazg","tag":"9CF_koFccgK6w9WZho_9eQ"},
      }
    ]
  },
  ecdh1PuV3Xc20PkwV2: {
    pass: [
      {
        senderkey: 'Ga6k9NGzLLbyz4uDF/25rmxL6kcMpIUfAB6q4jyErEI=',
        recipientkeys: [ 'eGftJuIHIOQ4pIhpdHGgqJAYGvNRQyL1UgbuHCJKrlw=' ],
        cleartext: '/GOQlvtSg2V6m9L1IfjPpoyunkmjtvzZX5/gh+lo847Ys3oP+1wd0NmAsCGHiSTB58aAx6PG1+Vi4sXUtRP4kw==',
        jwe: {"protected":"eyJlbmMiOiJYQzIwUCJ9","iv":"tqp15TShA-eDERy2qEgCLmDl1QJSDZ4j","ciphertext":"5jPbpy_tj3FVszRzrEHwc6J0o-KluNSa56zyN3D7EHiJ_hgQDwUN8B-U1AJ_1uaBuPBmV0e-zAE4iX9ils_POcvwdpEB0LVnJ6QPYoOdbMx94uLb6pd6xw","tag":"QAdzJ4M8bSqvvuYY9-H_tw","recipients":[{"encrypted_key":"R8CAGP5rj3IZsKHWnSKrb_Z5iFwtLvDIn_WqO3pIko0","header":{"alg":"ECDH-1PU+XC20PKW","iv":"uedotKy0c6EhJMrWZC8r4_60n-vqUdAK","tag":"BImFz89iFXrhX_OmwqZRPA","epk":{"kty":"OKP","crv":"X25519","x":"ZHdwr-bpjEIYvvmcVyTT-UvjJS1DxUOLMNo5CxjcQns"},"enc":"XC20P"}}]}
      },
      {
        senderkey: '4pJFgMDsu0JqjFT9l2NnFv+/Q/1qUP9dzt0lFdu1+00=',
        recipientkeys: [ 'G7MtaOo6BMsi8VoEgu4DEJmfgl088DIHLm6BbMFNnMk=' ],
        cleartext: '/GOQlvtSg2V6m9L1IfjPpoyunkmjtvzZX5/gh+lo847Ys3oP+1wd0NmAsCGHiSTB58aAx6PG1+Vi4sXUtRP4kw==',
        jwe: {"protected":"eyJza2lkIjoiZGlkOmV4YW1wbGU6c2VuZGVyI2tleS0xIiwiZW5jIjoiWEMyMFAifQ","iv":"4wcrBHUEBhhi1jYQWeGXzFSmf013CWjE","ciphertext":"nCCKJTjHI8IzNNC7OoCrKtXhkqzYUp2EeBkcSDy6rn4Z0oDc1-GAfJumQw83MO3aNKxEkF_iFEZiE6dlZKmvX5o9VDMk-pG8dd9gTlBS8Jx5V7GIotATkg","tag":"1U7BeQvvkGrK5idhUrwxOw","recipients":[{"encrypted_key":"2o2Ponu58YToFT1fi4jh6XADnLZK_2HV629zPB39FmY","header":{"alg":"ECDH-1PU+XC20PKW","iv":"DFTIc_GxomeBBNW0Ne5pYarqCFpCNEAQ","tag":"eGtKwjevonz39if11DIe3g","epk":{"kty":"OKP","crv":"X25519","x":"an9B9-jgsR53lrLIRVdgd2_AOglxnFv6JFmHhiBXniw"},"kid":"did:example:receiver#key-1","skid":"did:example:sender#key-1","enc":"XC20P"}}]}
      },
      {
        senderkey: 'o9+nnB/a7L7OaHpDKV3ZNqO8kMxN87bTfc3PPHwdmAY=',
        recipientkeys: [ 'aHCSf53GyAsi2NEPN7jSJCiBNPI6caFZSnTsARA2/JU=' ],
        cleartext: '/GOQlvtSg2V6m9L1IfjPpoyunkmjtvzZX5/gh+lo847Ys3oP+1wd0NmAsCGHiSTB58aAx6PG1+Vi4sXUtRP4kw==',
        jwe: {"protected":"eyJlbmMiOiJYQzIwUCJ9","iv":"Mv2AaWtIV9xKPkR0Z4YWwHbPWNYfkQUm","ciphertext":"bO4O_N4LDn0LXovMFr-YUIguYAOgRwEilWikeehEigMlHuRMhk9gXAxzgEXOVR3EeAY0rOiJBs3kM0lXbkibbq5jD7dkoTO8d4f9VwJTvjh1n5T7dIS_4g","tag":"Fp4irT84Ry261664HeDixQ","recipients":[{"encrypted_key":"xm_rMaWJbyi5d1Hy3DvGc-ShjBMmtBLBaBrgYbjbqqs","header":{"alg":"ECDH-1PU+XC20PKW","iv":"CfJBZwkmufgbkhH5RMmAGmnAO7_TeiEy","tag":"U1ffVZr8hhnAgJKmr9tgzA","epk":{"kty":"OKP","crv":"X25519","x":"ZtKE_n4apf8xJxPfrk_22fHeYz1oMVV-9Ilsjkt9GWQ"},"apu":"QWxpY2U","apv":"Qm9i","enc":"XC20P"}}]}
      },
      {
        senderkey: 'gEBhMCE0zlLPTPY6TW/X1nFC+6Gn22KSuqdj8xuMDC8=',
        recipientkeys: [ 'TnDUuo7hbVWYw/49HjZfWGDnDGZ/6tRdvwina0kYGwM=' ],
        cleartext: '/GOQlvtSg2V6m9L1IfjPpoyunkmjtvzZX5/gh+lo847Ys3oP+1wd0NmAsCGHiSTB58aAx6PG1+Vi4sXUtRP4kw==',
        jwe: {"protected":"eyJza2lkIjoiZGlkOmV4YW1wbGU6c2VuZGVyI2tleS0xIiwiZW5jIjoiWEMyMFAifQ","iv":"MDK1vppdO1fBhnWYBw5Vcj7OzXFoWLI6","ciphertext":"6orRa7wBlgRKsyaTxbHSEzphYRH_1HwC5FDJDsuBQ7Fv7XwAJ12gvkxSKx4HvFNRgcgsODmdjYGyQQFnkqswFyZwyNylYpJyh5bAaqV61Z7R79kYHuMRVg","tag":"NHflobCWt6lplerL8dj36w","recipients":[{"encrypted_key":"7swx_oZVz5Zwv1nfHx1ls8ZFaK2w-U-SbKN425GLrKQ","header":{"alg":"ECDH-1PU+XC20PKW","iv":"CgpZBwuh4UQMiE_ESRBdH7V9X4ZEo7cf","tag":"jm6l1jIaI8mOEn_wzTXHTQ","epk":{"kty":"OKP","crv":"X25519","x":"SGslzCO9UZ7p4jU3_jqgu-bHh7ojq0RxR3rswAhcvGo"},"kid":"did:example:receiver#key-1","apu":"QWxpY2U","apv":"Qm9i","skid":"did:example:sender#key-1","enc":"XC20P"}}]}
      },
      {
        senderkey: 'winSRtxUQasfBLcd8HPmF85kS6HMa0RLRtA8PblTsFc=',
        recipientkeys: [ '2EITYEbrM3CtbggjtIWb+XR1nXn33ak2f8x5U0+tUs8=' ],
        cleartext: '/GOQlvtSg2V6m9L1IfjPpoyunkmjtvzZX5/gh+lo847Ys3oP+1wd0NmAsCGHiSTB58aAx6PG1+Vi4sXUtRP4kw==',
        jwe: {"protected":"eyJtb3JlIjoicHJvdGVjdGVkIiwiZW5jIjoiWEMyMFAifQ","iv":"0AgTZOUg3yw0wayLySRVij8I7bDxQ0oZ","ciphertext":"3fYjaPgzawEdGbRir1dPzhTKNTtGlUvSkEFsW7wA3fpBrwN5qx3K_jyeixKkotOvn7kCG-NTgGAJ77ValW1Cl2X3fbb84YkYd1-UYr_qdBO_7-UELu145Q","tag":"H9h1pnOyWBpHUf76vnNobA","recipients":[{"encrypted_key":"mGqF1GmWGTzTQ1dtEHYuib1PEJs9bnezJBC0Qdw4Ih0","header":{"alg":"ECDH-1PU+XC20PKW","iv":"kQ9GZb3X3BGbf5KajtR7GhpW2Jneo1yp","tag":"cKZ6ilsGPmmA2X9rO3wOBQ","epk":{"kty":"OKP","crv":"X25519","x":"JhZV5gNSZ9LxoqKZ1tfkFUoisdqTUPpZXPThe-7pVnI"},"more":"protected","enc":"XC20P"}}]}
      },
      {
        senderkey: 'Jec1EkYpuvVj2vKXIyMjSo2JS7KXwMA1rvVGj7umYlw=',
        recipientkeys: [ 'L16P46IUqXyxbdG3vxq0HqwzBbMwkVU9/SKjRy7Nubo=' ],
        cleartext: '/GOQlvtSg2V6m9L1IfjPpoyunkmjtvzZX5/gh+lo847Ys3oP+1wd0NmAsCGHiSTB58aAx6PG1+Vi4sXUtRP4kw==',
        jwe: {"protected":"eyJtb3JlIjoicHJvdGVjdGVkIiwiZW5jIjoiWEMyMFAifQ","iv":"HtAxWrZXeFYQqhTX3VvTaPoo_iW78xhZ","ciphertext":"CPlGjk7prypqISuF0bMNgemNTG2JCLBrZbmsIAFBpqyUsJR9ZR6QA1osOb-ENZGqzem-TQvd8hn1EWtQiDBN_Sg8vt41GAfBvP3jYTxSvOMO4co2SZ864Q","tag":"6lvid-vUJHIIrTTdqtZWjQ","aad":"dGhpcyBkYXRhIGlzIGF1dGhlbnRpY2F0ZWQ","recipients":[{"encrypted_key":"-gFoPiUt1Ooqm6OfBxCS7zPntO_H13-a4fRah7OXNU4","header":{"alg":"ECDH-1PU+XC20PKW","iv":"WqVUpQgsjdkLeJ_9h3_cGq5F9bA49r84","tag":"OjXw26fPv6YYx0BAGK4r0w","epk":{"kty":"OKP","crv":"X25519","x":"yO4REF7yeuojtAgO7Zv4aBlopDhoId6RdKm4ByPYVG4"},"more":"protected","enc":"XC20P"}}]}
      },
      {
        senderkey: 's1mmgl42lUYs/m9NFcZXsrejKxpu0wpmExmskyXWsUQ=',
        recipientkeys: [ 'OG/mkqO2noX0/7E0I+HTHGMTpYxbPLG8X9ak7ADGOtY=', '0I452d/J7+xl5OB/4ZGXoRPKBwpJdvd7E20SGLy9IAQ=' ],
        cleartext: '/GOQlvtSg2V6m9L1IfjPpoyunkmjtvzZX5/gh+lo847Ys3oP+1wd0NmAsCGHiSTB58aAx6PG1+Vi4sXUtRP4kw==',
        jwe: {"protected":"eyJza2lkIjoiZGlkOmV4YW1wbGU6c2VuZGVyI2tleS0xIiwiZW5jIjoiWEMyMFAifQ","iv":"Hzl9pqbvncH10U6MFRpOZ7xyYqZTJkP_","ciphertext":"wvHImSFeFG6NpCEfpoAVe-DT8YgFPHt0dyPIS3nP3t6wY8A2GWf3z9-uzgX0ZVNr73_d0M_rhnPnBzlBiocsXrq7HLuBBucHoM2bC3NX2W_PoOoUHcf3zw","tag":"vDIWnftTdrkrHjiireD4aw","recipients":[{"encrypted_key":"DJYCzKQcf5heWMeOIcgVvCY99GVRMAcsrXsuElKK54s","header":{"alg":"ECDH-1PU+XC20PKW","iv":"XdcU-TJ2ZflgIDmQBJUDyDvHSCKdZpur","tag":"lGHm5Iofs-RZaGp3N4z0dQ","epk":{"kty":"OKP","crv":"X25519","x":"ZKI_CUgkKm2BSGZl61wCU8C94eiJMBYLZqZzFDTTJy4"},"kid":"did:example:receiver1#key-1","skid":"did:example:sender#key-1","enc":"XC20P"}},{"encrypted_key":"6hTnZ6Lw1PUtWXISFMTqI8BmQ9TQo3svwiC5CI8dhcg","header":{"alg":"ECDH-1PU+XC20PKW","iv":"ZgGZNiv_Zcm-dnoNl3keXAXMPO-ZSuAb","tag":"-zU7jiF-tNWdI7oDVzk52Q","epk":{"kty":"OKP","crv":"X25519","x":"oP9HpmTjYJpDvK1TJN0u9bZH70E7RLRVsx47-5zosUk"},"kid":"did:example:receiver2#key-1","skid":"did:example:sender#key-1","enc":"XC20P"}}]}
      },
      {
        senderkey: 'L9q9/9Ja+sRXsgtaoJu4BKsU4tPShkD43q2q/J6QhS8=',
        recipientkeys: [ 'NDj9lf1KGYV62+suEaV7eM9Jyf52IcNOgfk/gq2ZM88=', 'FjYBTXCaNXqOafuznKOiDsdza6seF6O1THL/aaOCoQ0=' ],
        cleartext: '/GOQlvtSg2V6m9L1IfjPpoyunkmjtvzZX5/gh+lo847Ys3oP+1wd0NmAsCGHiSTB58aAx6PG1+Vi4sXUtRP4kw==',
        jwe: {"protected":"eyJtb3JlIjoicHJvdGVjdGVkIiwic2tpZCI6ImRpZDpleGFtcGxlOnNlbmRlciNrZXktMSIsImVuYyI6IlhDMjBQIn0","iv":"BN5rEL2D8n6O4X5qFVD1NgspGtKABgXR","ciphertext":"lNbDB1MsqC654o5vuV2NlYjXp26WgPcYMWxU2xx1lTIuK1V3loF3vrRG7gItxWQp3KHJL4TZVYcGd29hFkB_Aw4JIp2t1-sLtjPsvs7P9hf0I-60Em3pFA","tag":"U2gFdvyJgTbhnt3WxIZv6A","recipients":[{"encrypted_key":"GoUONl8e-5lkG9nl4xgCmyGCJG6cR3l-PsTpWFAJ2-4","header":{"alg":"ECDH-1PU+XC20PKW","iv":"QHMSdRjuHQamlyiDG11xdI6ZRbMXxrd1","tag":"F7N6Gr_3kbS5uscGgrNEkg","epk":{"kty":"OKP","crv":"X25519","x":"4__NuoaZRG124GpJYReph2VsYSRYELNYiLIf6hXtVXQ"},"kid":"did:example:receiver1#key-1","more":"protected","skid":"did:example:sender#key-1","enc":"XC20P"}},{"encrypted_key":"H2GfRVKHOwdEsmvSoZWu7jP1Y--kwh3nKYMUtBiQzM8","header":{"alg":"ECDH-1PU+XC20PKW","iv":"gTF_tpp8FIOKqGItFwilpOhEhOErqa9j","tag":"mKP5Ey4c0CEt6R0inWhuRA","epk":{"kty":"OKP","crv":"X25519","x":"BGB0V4X_XJLVV5fXM-CbGyF6x7EQh4fWE6NxdAueXSE"},"kid":"did:example:receiver2#key-1"}}]}
      },
      {
        senderkey: 'DMk0fWkt2Y8Y717xbUps8o+g9vXgqhIvUzG22u3YoVQ=',
        recipientkeys: [ 'aK2tDSxuQB3wE0+pW2xhez+jd2Nlnlsn40TfmG/290A=', 'MBJmtMzmfH86xjiuFZ7yObzhUlWZyTSkXgNvClB7Nz8=' ],
        cleartext: '/GOQlvtSg2V6m9L1IfjPpoyunkmjtvzZX5/gh+lo847Ys3oP+1wd0NmAsCGHiSTB58aAx6PG1+Vi4sXUtRP4kw==',
        jwe: {"protected":"eyJtb3JlIjoicHJvdGVjdGVkIiwic2tpZCI6ImRpZDpleGFtcGxlOnNlbmRlciNrZXktMSIsImVuYyI6IlhDMjBQIn0","iv":"WEAjww6hpVW-q0qOHDtEEN-AwWVEkHgf","ciphertext":"OuSj8p9DJ2O4cOXRWHi3bLQbnsTRNuSKjgAr5ig1AcsXRj0olOOEK-gb5Qs7sNREUUBqUyK9SC2_cW2JD5BC-MKal08eriN7N2e-m5SS9OOIsZiyGtnI-A","tag":"MHAFgLIHcNS-m42OiVvNwQ","aad":"dGhpcyBkYXRhIGlzIGF1dGhlbnRpY2F0ZWQ","recipients":[{"encrypted_key":"puuKXBUXSBlRZCICaQnG-OLX_F_-GVE4lESLqZ4QDTk","header":{"alg":"ECDH-1PU+XC20PKW","iv":"zZqI4m9XO-aA6u2EVEZUGJexnMuSnxC4","tag":"HDZdndyMdRf77I2IO-zUow","epk":{"kty":"OKP","crv":"X25519","x":"KZfzLUZMwvlc7mItQyx0F9b1caC0SxiGuNemmYQ8nF8"},"kid":"did:example:receiver1#key-1","more":"protected","skid":"did:example:sender#key-1","enc":"XC20P"}},{"encrypted_key":"X85SlJ6WEJv4TFTxn2SYH1w0fEKH_HkI_oZZaK_VglE","header":{"alg":"ECDH-1PU+XC20PKW","iv":"HtBD10hnvYwqFB7BcHe9PPrOAV4qybHZ","tag":"p0ySr_KDlUWRAwSwE2ifNQ","epk":{"kty":"OKP","crv":"X25519","x":"zAkbzcZYPveVuE5nEiNGq4bN8Ja3ImJG_BI0UkTs_ys"},"kid":"did:example:receiver2#key-1","more":"protected","skid":"did:example:sender#key-1","enc":"XC20P"}}]}
      }
    ],
    fail: [
      {
        // wrong sender key
        senderkey: 'DMk0fWkt2Y8Y717xbUps8o+g9vXgqhIvUzG22u3YoVQ=',
        recipientkeys: [ 'eGftJuIHIOQ4pIhpdHGgqJAYGvNRQyL1UgbuHCJKrlw=' ],
        cleartext: '/GOQlvtSg2V6m9L1IfjPpoyunkmjtvzZX5/gh+lo847Ys3oP+1wd0NmAsCGHiSTB58aAx6PG1+Vi4sXUtRP4kw==',
        jwe: {"protected":"eyJlbmMiOiJYQzIwUCJ9","iv":"tqp15TShA-eDERy2qEgCLmDl1QJSDZ4j","ciphertext":"5jPbpy_tj3FVszRzrEHwc6J0o-KluNSa56zyN3D7EHiJ_hgQDwUN8B-U1AJ_1uaBuPBmV0e-zAE4iX9ils_POcvwdpEB0LVnJ6QPYoOdbMx94uLb6pd6xw","tag":"QAdzJ4M8bSqvvuYY9-H_tw","recipients":[{"encrypted_key":"R8CAGP5rj3IZsKHWnSKrb_Z5iFwtLvDIn_WqO3pIko0","header":{"alg":"ECDH-1PU+XC20PKW","iv":"uedotKy0c6EhJMrWZC8r4_60n-vqUdAK","tag":"BImFz89iFXrhX_OmwqZRPA","epk":{"kty":"OKP","crv":"X25519","x":"ZHdwr-bpjEIYvvmcVyTT-UvjJS1DxUOLMNo5CxjcQns"},"enc":"XC20P"}}]}
      },
      {
        // wrong recipient keys
        senderkey: 'Ga6k9NGzLLbyz4uDF/25rmxL6kcMpIUfAB6q4jyErEI=',
        recipientkeys: [ 'aK2tDSxuQB3wE0+pW2xhez+jd2Nlnlsn40TfmG/290A=' ],
        cleartext: '/GOQlvtSg2V6m9L1IfjPpoyunkmjtvzZX5/gh+lo847Ys3oP+1wd0NmAsCGHiSTB58aAx6PG1+Vi4sXUtRP4kw==',
        jwe: {"protected":"eyJlbmMiOiJYQzIwUCJ9","iv":"tqp15TShA-eDERy2qEgCLmDl1QJSDZ4j","ciphertext":"5jPbpy_tj3FVszRzrEHwc6J0o-KluNSa56zyN3D7EHiJ_hgQDwUN8B-U1AJ_1uaBuPBmV0e-zAE4iX9ils_POcvwdpEB0LVnJ6QPYoOdbMx94uLb6pd6xw","tag":"QAdzJ4M8bSqvvuYY9-H_tw","recipients":[{"encrypted_key":"R8CAGP5rj3IZsKHWnSKrb_Z5iFwtLvDIn_WqO3pIko0","header":{"alg":"ECDH-1PU+XC20PKW","iv":"uedotKy0c6EhJMrWZC8r4_60n-vqUdAK","tag":"BImFz89iFXrhX_OmwqZRPA","epk":{"kty":"OKP","crv":"X25519","x":"ZHdwr-bpjEIYvvmcVyTT-UvjJS1DxUOLMNo5CxjcQns"},"enc":"XC20P"}}]}
      },
      {
        // wrong sender key
        senderkey: 'DMk0fWkt2Y8Y717xbUps8o+g9vXgqhIvUzG22u3YoVQ=',
        recipientkeys: [ 'OG/mkqO2noX0/7E0I+HTHGMTpYxbPLG8X9ak7ADGOtY=', '0I452d/J7+xl5OB/4ZGXoRPKBwpJdvd7E20SGLy9IAQ=' ],
        cleartext: '/GOQlvtSg2V6m9L1IfjPpoyunkmjtvzZX5/gh+lo847Ys3oP+1wd0NmAsCGHiSTB58aAx6PG1+Vi4sXUtRP4kw==',
        jwe: {"protected":"eyJza2lkIjoiZGlkOmV4YW1wbGU6c2VuZGVyI2tleS0xIiwiZW5jIjoiWEMyMFAifQ","iv":"Hzl9pqbvncH10U6MFRpOZ7xyYqZTJkP_","ciphertext":"wvHImSFeFG6NpCEfpoAVe-DT8YgFPHt0dyPIS3nP3t6wY8A2GWf3z9-uzgX0ZVNr73_d0M_rhnPnBzlBiocsXrq7HLuBBucHoM2bC3NX2W_PoOoUHcf3zw","tag":"vDIWnftTdrkrHjiireD4aw","recipients":[{"encrypted_key":"DJYCzKQcf5heWMeOIcgVvCY99GVRMAcsrXsuElKK54s","header":{"alg":"ECDH-1PU+XC20PKW","iv":"XdcU-TJ2ZflgIDmQBJUDyDvHSCKdZpur","tag":"lGHm5Iofs-RZaGp3N4z0dQ","epk":{"kty":"OKP","crv":"X25519","x":"ZKI_CUgkKm2BSGZl61wCU8C94eiJMBYLZqZzFDTTJy4"},"kid":"did:example:receiver1#key-1","skid":"did:example:sender#key-1","enc":"XC20P"}},{"encrypted_key":"6hTnZ6Lw1PUtWXISFMTqI8BmQ9TQo3svwiC5CI8dhcg","header":{"alg":"ECDH-1PU+XC20PKW","iv":"ZgGZNiv_Zcm-dnoNl3keXAXMPO-ZSuAb","tag":"-zU7jiF-tNWdI7oDVzk52Q","epk":{"kty":"OKP","crv":"X25519","x":"oP9HpmTjYJpDvK1TJN0u9bZH70E7RLRVsx47-5zosUk"},"kid":"did:example:receiver2#key-1","skid":"did:example:sender#key-1","enc":"XC20P"}}]}
      },
      {
        // wrong recipient keys
        senderkey: 's1mmgl42lUYs/m9NFcZXsrejKxpu0wpmExmskyXWsUQ=',
        recipientkeys: [ 'aK2tDSxuQB3wE0+pW2xhez+jd2Nlnlsn40TfmG/290A=', 'aK2tDSxuQB3wE0+pW2xhez+jd2Nlnlsn40TfmG/290A=' ],
        cleartext: '/GOQlvtSg2V6m9L1IfjPpoyunkmjtvzZX5/gh+lo847Ys3oP+1wd0NmAsCGHiSTB58aAx6PG1+Vi4sXUtRP4kw==',
        jwe: {"protected":"eyJza2lkIjoiZGlkOmV4YW1wbGU6c2VuZGVyI2tleS0xIiwiZW5jIjoiWEMyMFAifQ","iv":"Hzl9pqbvncH10U6MFRpOZ7xyYqZTJkP_","ciphertext":"wvHImSFeFG6NpCEfpoAVe-DT8YgFPHt0dyPIS3nP3t6wY8A2GWf3z9-uzgX0ZVNr73_d0M_rhnPnBzlBiocsXrq7HLuBBucHoM2bC3NX2W_PoOoUHcf3zw","tag":"vDIWnftTdrkrHjiireD4aw","recipients":[{"encrypted_key":"DJYCzKQcf5heWMeOIcgVvCY99GVRMAcsrXsuElKK54s","header":{"alg":"ECDH-1PU+XC20PKW","iv":"XdcU-TJ2ZflgIDmQBJUDyDvHSCKdZpur","tag":"lGHm5Iofs-RZaGp3N4z0dQ","epk":{"kty":"OKP","crv":"X25519","x":"ZKI_CUgkKm2BSGZl61wCU8C94eiJMBYLZqZzFDTTJy4"},"kid":"did:example:receiver1#key-1","skid":"did:example:sender#key-1","enc":"XC20P"}},{"encrypted_key":"6hTnZ6Lw1PUtWXISFMTqI8BmQ9TQo3svwiC5CI8dhcg","header":{"alg":"ECDH-1PU+XC20PKW","iv":"ZgGZNiv_Zcm-dnoNl3keXAXMPO-ZSuAb","tag":"-zU7jiF-tNWdI7oDVzk52Q","epk":{"kty":"OKP","crv":"X25519","x":"oP9HpmTjYJpDvK1TJN0u9bZH70E7RLRVsx47-5zosUk"},"kid":"did:example:receiver2#key-1","skid":"did:example:sender#key-1","enc":"XC20P"}}]}
      }
    ],
    invalid: [
      {
        jwe: {"protected":"eyJtb3JlIjoicHJvdGVjdGVkIiwic2tpZCI6ImRpZDpleGFtcGxlOnNlbmRlciNrZXktMSIsImVuYyI6IlhDMjBQIn0","ciphertext":"6DehIR6ps5yh5Mepwj6XluBSk5AS0d18Y27XTWvV5T0uCRtcxBGO1finKBqzgblJA7dPQ55TZuVd41UERiq9FhsPgp7ehR4bBoyHnm8ftnjSHVpyORxLBw","tag":"T2fKAQQgJGFpI0kfpGXFkg","aad":"dGhpcyBkYXRhIGlzIGF1dGhlbnRpY2F0ZWQ","recipients":[{"encrypted_key":"OKUxwt7G1VbLhl0K5yHGkEQe2Ii8CHblLREK304ub6M","header":{"alg":"ECDH-1PU+XC20PKW","iv":"Gnt5p0e8eG012SfLxh-uo9lKs8cYsYGy","tag":"XWZYufnclg_Ei4JsBMpYNA","epk":{"kty":"OKP","crv":"X25519","x":"u7j3sQuuUbDVFoujne22_1b9HcwHkbAUxRsyAmhGz14"},"kid":"did:example:receiver#key-1","apu":"ZGlkOmV4YW1wbGU6c2VuZGVyI2tleS0x","apv":"ZGlkOmV4YW1wbGU6cmVjZWl2ZXIja2V5LTE","more":"protected","skid":"did:example:sender#key-1","enc":"XC20P"}}]}
      },
      {
        jwe: {"protected":"eyJtb3JlIjoicHJvdGVjdGVkIiwic2tpZCI6ImRpZDpleGFtcGxlOnNlbmRlciNrZXktMSIsImVuYyI6IlhDMjBQIn0","iv":"yZakU656sGJS9UKV5zyC1HV7cIhu0MPs","ciphertext":"6DehIR6ps5yh5Mepwj6XluBSk5AS0d18Y27XTWvV5T0uCRtcxBGO1finKBqzgblJA7dPQ55TZuVd41UERiq9FhsPgp7ehR4bBoyHnm8ftnjSHVpyORxLBw","tag":"T2fKAQQgJGFpI0kfpGXFkg","aad":"dGhpcyBkYXRhIGlzIGF1dGhlbnRpY2F0ZWQ","recipients":[]}
      },
      {
        jwe: {"protected":"eyJtb3JlIjoicHJvdGVjdGVkIiwic2tpZCI6ImRpZDpleGFtcGxlOnNlbmRlciNrZXktMSIsImVuYyI6IlhDMjBQIn0","iv":"yZakU656sGJS9UKV5zyC1HV7cIhu0MPs","ciphertext":"6DehIR6ps5yh5Mepwj6XluBSk5AS0d18Y27XTWvV5T0uCRtcxBGO1finKBqzgblJA7dPQ55TZuVd41UERiq9FhsPgp7ehR4bBoyHnm8ftnjSHVpyORxLBw","aad":"dGhpcyBkYXRhIGlzIGF1dGhlbnRpY2F0ZWQ","recipients":[{"encrypted_key":"OKUxwt7G1VbLhl0K5yHGkEQe2Ii8CHblLREK304ub6M","header":{"alg":"ECDH-1PU+XC20PKW","iv":"Gnt5p0e8eG012SfLxh-uo9lKs8cYsYGy","tag":"XWZYufnclg_Ei4JsBMpYNA","epk":{"kty":"OKP","crv":"X25519","x":"u7j3sQuuUbDVFoujne22_1b9HcwHkbAUxRsyAmhGz14"},"kid":"did:example:receiver#key-1","apu":"ZGlkOmV4YW1wbGU6c2VuZGVyI2tleS0x","apv":"ZGlkOmV4YW1wbGU6cmVjZWl2ZXIja2V5LTE","more":"protected","skid":"did:example:sender#key-1","enc":"XC20P"}}]}
      }
    ]
  }  
}
