namespace IdentityApi.Models;

public class JWTSettings
{
    public string Key { get; set; }
    public int ExpireSeconds { get; set; }
}