from o365_connector.utils.secrets import env_var_for_tenant


def test_env_var_for_tenant():
    assert env_var_for_tenant("1234-5678-90ab") == "O365_SECRET_1234_5678_90AB"
    assert env_var_for_tenant("Contoso.com") == "O365_SECRET_CONTOSO_COM"
