#region License
// IAuthenticationDataProvider.cs
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
    /// Represents the data provider of the <see cref="Authentication"/> class.
    /// Usually data provider should implement IDisposable in order to release expensive resource at the end.
    /// </summary>
    public interface IAuthenticationDataProvider : IDisposable
    {
        /// <summary>
        /// Gets the user.
        /// </summary>
        /// <param name="name">The name.</param>
        /// <returns></returns>
        IUser GetUser(string name);

        /// <summary>
        /// Gets the user.
        /// </summary>
        /// <param name="name">The name.</param>
        /// <param name="password">The password.</param>
        /// <returns></returns>
        IUser GetUser(string name, string password);

        /// <summary>
        /// Gets the user by name or email.
        /// </summary>
        /// <param name="nameOrEmail">The name or email.</param>
        /// <param name="password">The password.</param>
        /// <returns></returns>
        IUser GetUserByNameOrEmail(string nameOrEmail, string password);

        /// <summary>
        /// Updates the user last activity time.
        /// </summary>
        /// <param name="name">The name.</param>
        void UpdateUserLastActivityTime(string name);

        /// <summary>
        /// Updates the user.
        /// </summary>
        /// <param name="name">The name.</param>
        void UpdateUserLastLoginTime(string name);
    }
}
