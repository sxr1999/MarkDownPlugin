using IdentityApi.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityApi.DbContext;

public class MyDbContext : IdentityDbContext<MyUser,MyRole,long>
{
    public MyDbContext(DbContextOptions<MyDbContext> options) : base(options)
    {
        
    }

    public DbSet<MyUser> MyUsers { get; set; }
    public DbSet<MyRole> MyRoles { get; set; }
}