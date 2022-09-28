using Microsoft.AspNetCore.Identity;

namespace IdentityApi.Models;

public class MyUser : IdentityUser<long>
{
    public long JWTVersion { get; set; }
}