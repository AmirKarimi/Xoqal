#region License
// IAuthentication.cs
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
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// Represents an authentication manager.
    /// </summary>
    public interface IAuthentication
    {
        /// <summary>
        /// Gets or sets the data provider.
        /// </summary>
        /// <value>
        /// The data provider.
        /// </value>
        IAuthenticationDataProvider DataProvider { get; }

        /// <summary>
        /// Validates the user.
        /// </summary>
        /// <param name="name">The name.</param>
        /// <param name="password">The password.</param>
        /// <returns></returns>
        bool ValidateUser(string name, string password);

        /// <summary>
        /// Authenticates the specified user.
        /// </summary>
        /// <param name="name"> Name of the user. </param>
        /// <param name="password"> The password. </param>
        /// <param name="remember"> The value indicating whether remember the credential or not. </param>
        /// <returns> </returns>
        bool Authenticate(string name, string password, bool remember = false);

        /// <summary>
        /// Authenticates the specified user.
        /// </summary>
        /// <param name="name"> Name of the user. </param>
        /// <param name="remember"> The value indicating whether remember the credential or not. </param>
        /// <returns> </returns>
        bool Authenticate(string name, bool remember = false);

        /// <summary>
        /// Authenticates the specified user with its username or password.
        /// </summary>
        /// <param name="usernameOrEmail"> Name of the user. </param>
        /// <param name="password"> The password. </param>
        /// <param name="remember">The remember. </param>
        /// <returns> </returns>
        bool AuthenticateByNameOrEmail(string usernameOrEmail, string password, bool remember = false);

        /// <summary>
        /// Signs out the current user principal.
        /// </summary>
        void Logout();

        /// <summary>
        /// Gets the current user principal.
        /// </summary>
        /// <returns> </returns>
        IUserPrincipal GetCurrentUserPrincipal(bool updateLastActivityTime = true);

        /// <summary>
        /// Determines whether the current user principal has the specified permissions.
        /// </summary>
        /// <param name="permissionItems">The permission items.</param>
        /// <returns>
        /// <c>true</c> if the current user principal has the specified permissions; otherwise, <c>false</c>.
        /// </returns>
        bool IsUserInPermission(params PermissionItem[] permissionItems);

        /// <summary>
        /// Determines whether the current user principal has the specified permissions.
        /// </summary>
        /// <param name="permissions">The permissions.</param>
        /// <returns>
        /// <c>true</c> if the current user principal has the specified permissions; otherwise, <c>false</c>.
        /// </returns>
        bool IsUserInPermission(params string[] permissions);

        /// <summary>
        /// Determines whether the current user principal has the specified roles.
        /// </summary>
        /// <param name="roles">The roles.</param>
        /// <returns>
        /// <c>true</c> if the current user principal has the specified roles; otherwise, <c>false</c>.
        /// </returns>
        bool IsUserInRole(params string[] roles);
    }
}
