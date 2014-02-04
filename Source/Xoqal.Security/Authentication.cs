#region License
// Authentication.cs
// 
// Copyright (c) 2012 Xoqal.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#endregion

namespace Xoqal.Security
{
    using System;
    using System.Linq;
    using System.Security.Principal;
    using System.Threading;
    using System.Web;
    using System.Web.Security;

    /// <summary>
    /// Authentication manager.
    /// </summary>
    public class Authentication : IAuthentication
    {
        #region Fields
        
        private static IAuthentication defaultInstance;
        private static IPrincipal globalPrincipal;

        #endregion

        #region Properties
        
        /// <summary>
        /// Responsible for initializing  IAuthenticationDataProvider.
        /// It should be populated in application bootstrap
        /// </summary>
        /// <remarks>
        /// a proper DI container should take the lifetime responsibility of an object that put to this class through 
        /// this delegate.
        /// </remarks>
        /// <example>
        /// var container = new WindsorContainer();
        /// 
        /// container.Register(Component.For<IAuthenticationDataProvider>()
        ///                             .ImplementedBy<AuthenticationDataProvider>()
        ///                             .LifeStyle.HybridPerWebRequestPerThread());
        /// 
        /// Xoqal.Security.Authentication.DataProviderInitializer = () =>
        ///     {
        ///         return container.Resolve<IAuthenticationDataProvider>();
        ///     };
        /// </example>
        public static Func<IAuthenticationDataProvider> DataProviderInitializer { get; set; }

        /// <summary>
        /// Gets the default instance.
        /// </summary>
        /// <value>
        /// The default.
        /// </value>
        public static IAuthentication Default
        {
            get
            {
                return Authentication.defaultInstance ?? (Authentication.defaultInstance = new Authentication());
            }
        }

        /// <summary>
        /// Get the DataProvider instance (for current thread)
        /// </summary>
        /// <remarks>
        /// Set by DataProviderInitializer factory
        /// </remarks>
        public IAuthenticationDataProvider DataProvider
        {
            get { return DataProviderInitializer.Invoke(); }
        }

        #endregion

        #region Public Members

        /// <summary>
        /// Validates the user.
        /// </summary>
        /// <param name="name">The name.</param>
        /// <param name="password">The password.</param>
        /// <returns></returns>
        public bool ValidateUser(string name, string password)
        {
            this.ValidateDataProvider();

            var user = this.DataProvider.GetUser(name, PasswordHasherFactory.Default.Hash(password));
            return user != null;
        }

        /// <summary>
        /// Authenticates the specified user.
        /// </summary>
        /// <param name="name"> Name of the user. </param>
        /// <param name="password"> The password. </param>
        /// <param name="remember"> The value indicating whether remember the credential or not. </param>
        /// <returns> </returns>
        public bool Authenticate(string name, string password, bool remember = false)
        {
            this.ValidateDataProvider();
            
            var user = this.DataProvider.GetUser(name, PasswordHasherFactory.Default.Hash(password));

            if (user == null || !user.IsActive)
            {
                return false;
            }

            this.SetCurrentUser(user, remember);

            return true;
        }

        /// <summary>
        /// Authenticates the specified user.
        /// </summary>
        /// <param name="name"> Name of the user. </param>
        /// <param name="remember"> The value indicating whether remember the credential or not. </param>
        /// <returns> </returns>
        public bool Authenticate(string name, bool remember = false)
        {
            this.ValidateDataProvider();

            var user = this.DataProvider.GetUser(name);

            if (user == null || !user.IsActive)
            {
                return false;
            }

            this.SetCurrentUser(user, remember);

            return true;
        }

        /// <summary>
        /// Authenticates the specified user with its username or password.
        /// </summary>
        /// <param name="usernameOrEmail"> Name of the user. </param>
        /// <param name="password"> The password. </param>
        /// <param name="remember">The remember. </param>
        /// <returns> </returns>
        public bool AuthenticateByNameOrEmail(string usernameOrEmail, string password, bool remember = false)
        {
            this.ValidateDataProvider();
            
            var user = this.DataProvider.GetUserByNameOrEmail(usernameOrEmail, PasswordHasherFactory.Default.Hash(password));

            if (user == null || !user.IsActive)
            {
                return false;
            }

            this.SetCurrentUser(user, remember);

            return true;
        }

        /// <summary>
        /// Signs out the current user.
        /// </summary>
        public void Logout()
        {
            this.ValidateDataProvider();
            
            var principal = this.GetCurrentPrincipal();

            if (principal == null)
            {
                return;
            }

            var user = this.DataProvider.GetUser(principal.Identity.Name);
            if (user != null)
            {
                this.DataProvider.UpdateUserLastActivityTime(user.UserName);
            }

            this.SetCurrentPrincipal(null);
            if (HttpContext.Current != null)
            {
                FormsAuthentication.SignOut();
            }
        }

        /// <summary>
        /// Gets the current user.
        /// </summary>
        /// <returns> </returns>
        public IUserPrincipal GetCurrentUserPrincipal(bool updateLastActivityTime = true)
        {
            this.ValidateDataProvider();

            IUserPrincipal userPrincipal;
            IUser user;
            this.GetCurrentUser(out userPrincipal, out user, updateLastActivityTime);

            return userPrincipal;
        }

        /// <summary>
        /// Determines whether the current user principal has the specified permissions.
        /// </summary>
        /// <param name="permissionItems">The permission items.</param>
        /// <returns>
        /// <c>true</c> if the current user principal has the specified permissions; otherwise, <c>false</c>.
        /// </returns>
        public bool IsUserInPermission(params PermissionItem[] permissionItems)
        {
            return this.IsUserInPermission(permissionItems.Select(p => p.PermissionId).ToArray());
        }

        /// <summary>
        /// Determines whether the current user principal has the specified permissions.
        /// </summary>
        /// <param name="permissions">The permissions.</param>
        /// <returns>
        /// <c>true</c> if the current user principal has the specified permissions; otherwise, <c>false</c>.
        /// </returns>
        public bool IsUserInPermission(params string[] permissions)
        {
            var user = this.GetCurrentUserPrincipal();
            if (user == null)
            {
                return false;
            }

            return permissions.Any(user.IsInPermission);
        }

        /// <summary>
        /// Determines whether the current user principal has the specified roles.
        /// </summary>
        /// <param name="roles">The roles.</param>
        /// <returns>
        /// <c>true</c> if the current user principal has the specified roles; otherwise, <c>false</c>.
        /// </returns>
        public bool IsUserInRole(params string[] roles)
        {
            var user = this.GetCurrentUserPrincipal();
            if (user == null)
            {
                return false;
            }

            return roles.Any(user.IsInRole);
        }

        #endregion

        #region Private Members

        /// <summary>
        /// Gets the current user.
        /// </summary>
        /// <param name="userPrincipal"></param>
        /// <param name="userEntity"></param>
        /// <param name="updateLastActivityTime"></param>
        private void GetCurrentUser(out IUserPrincipal userPrincipal, out IUser userEntity, bool updateLastActivityTime)
        {
            this.ValidateDataProvider();

            userPrincipal = null;
            userEntity = null;
            var principal = this.GetCurrentPrincipal();

            if (principal == null || string.IsNullOrWhiteSpace(principal.Identity.Name))
            {
                return;
            }

            userPrincipal = principal as IUserPrincipal;
            if (userPrincipal != null && !updateLastActivityTime)
            {
                return;
            }

            userEntity = this.DataProvider.GetUser(principal.Identity.Name);
            if (userEntity == null)
            {
                return;
            }

            if (updateLastActivityTime)
            {
                this.DataProvider.UpdateUserLastActivityTime(userEntity.UserName);
            }

            if (userPrincipal == null)
            {
                userPrincipal = this.CreateUserPrincipal(userEntity);
                Thread.CurrentPrincipal = userPrincipal;
                HttpContext.Current.User = userPrincipal;
            }
        }

        /// <summary>
        /// Gets the current principal.
        /// </summary>
        /// <returns></returns>
        private IPrincipal GetCurrentPrincipal()
        {
            if (HttpContext.Current == null)
            {
                return Authentication.globalPrincipal;
            }

            return Thread.CurrentPrincipal;
        }

        /// <summary>
        /// Creates an <see cref="IUserPrincipal"/> from the specified user.
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        private IUserPrincipal CreateUserPrincipal(IUser user)
        {
            return new UserPrincipal(
                new UserIdentity(user.Id, user.UserName),
                user.Roles.Select(r => r.Name).ToArray(),
                user.Roles.SelectMany(r => r.RolesInPermissions).Select(p => p.PermissionId).Distinct().ToArray());
        }

        /// <summary>
        /// Sets the current user.
        /// </summary>
        /// <param name="user"> The user. </param>
        /// <param name="remember">The remember. </param>
        private void SetCurrentUser(IUser user, bool remember)
        {
            var principal = this.CreateUserPrincipal(user);
            this.SetCurrentPrincipal(principal, remember);

            if (HttpContext.Current != null)
            {
                if (principal == null)
                {
                    FormsAuthentication.SignOut();
                }
                else
                {
                    FormsAuthentication.SetAuthCookie(principal.Identity.Name, remember);
                }
            }

            if (principal != null)
            {
                this.DataProvider.UpdateUserLastLoginTime(user.UserName);
                this.DataProvider.UpdateUserLastActivityTime(user.UserName);
            }
        }

        /// <summary>
        /// Sets the current principal.
        /// </summary>
        /// <param name="principal"> The principal. </param>
        /// <param name="remember"> if set to <c>true</c> remember the authentication. </param>
        private void SetCurrentPrincipal(IPrincipal principal, bool remember = false)
        {
            if (HttpContext.Current == null)
            {
                // Not web environment
                Authentication.globalPrincipal = principal;
            }
            else
            {
                // Web environment
                Thread.CurrentPrincipal = principal;
            }
        }

        /// <summary>
        /// Validates the data provider.
        /// </summary>
        private void ValidateDataProvider()
        {
            if (this.DataProvider == null)
            {
                throw new Exception("AuthenticationDataProvider is not set.");
            }
        }

        #endregion
    }
}
