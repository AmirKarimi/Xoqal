#region License
// LambdaExpressions.cs
// 
// Copyright (c) 2013 Xoqal.com
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

namespace Xoqal.Utilities.Linq
{
    using System;
    using System.Linq.Expressions;

    public static class LambdaExpressions
    {
        /// <summary>
        /// Gets property name of an expression
        /// </summary>
        /// <typeparam name="TSource">the source type to extract property name</typeparam>
        /// <typeparam name="TField">the field type of the expected property</typeparam>
        /// <param name="field">the expression to extract property name</param>
        /// <returns>indicated property name</returns>
        /// <example>
        /// Expression<Func<IPaginated, object>> rowCountProperty = arg => arg.TotalRowsCount;
        /// string pNamed = GetPropertyName<IPaginated, object>(rowCountProperty);
        /// </example>
        public static string GetPropertyName<TSource, TField>(Expression<Func<TSource, TField>> field)
        {
            return
                (field.Body as MemberExpression ??
                 ((UnaryExpression)field.Body).Operand as MemberExpression).Member
                                                                            .Name;
        }
    }
}
