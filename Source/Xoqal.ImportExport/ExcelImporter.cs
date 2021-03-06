#region License
// ExcelImporter.cs
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

namespace Xoqal.ExportImport
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.Linq;
    using System.Text;
    using ClosedXML.Excel;
    using Xoqal.Globalization;

    /// <summary>
    /// Imports a general data from an excel file.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class ExcelImporter<T> : ExcelImporterBase<T>
        where T : class, new()
    {
        /// <summary>
        /// Import the data.
        /// </summary>
        /// <returns>Imported data.</returns>
        protected override IEnumerable<T> Import()
        {
            List<T> importLoadingLists = new List<T>();

            foreach (var row in this.Worksheet.Rows())
            {
                T importedRecord = new T();
                var properties = TypeDescriptor.GetProperties(typeof(T));

                int column = 1;
                foreach (PropertyDescriptor property in properties)
                {
                    object value = this.GetCellValue(row, column);
                    this.SetPropertyValue(property, importedRecord, value);

                    column++;
                }

                yield return importedRecord;
            }
        }

        /// <summary>
        /// Sets the property value.
        /// </summary>
        /// <param name="property"></param>
        /// <param name="component"></param>
        /// <param name="value"></param>
        private void SetPropertyValue(PropertyDescriptor property, object component, object value)
        {
            if (property.PropertyType == typeof(DateTime) || property.PropertyType == typeof(DateTime?))
            {
                DateTime? dateTimeValue = null;
                if (GlobalDateTime.GetCalendar() is System.Globalization.PersianCalendar)
                {
                    dateTimeValue = PersianDateHelper.ParsePersianDate(value.ToString());
                }
                else
                {
                    DateTime dt;
                    if (DateTime.TryParse(value.ToString(), out dt))
                    {
                        dateTimeValue = dt;
                    }
                }

                property.SetValue(component, dateTimeValue);
                return;
            }

            if (property.Converter.CanConvertFrom(value.GetType()))
            {
                property.SetValue(component, property.Converter.ConvertFrom(value));
                return;
            }

            property.SetValue(component, value);
        }

        /// <summary>
        /// Gets the cell value.
        /// </summary>
        /// <param name="row">The row.</param>
        /// <param name="columnLetter">The column letter.</param>
        /// <returns></returns>
        private object GetCellValue(ClosedXML.Excel.IXLRow row, int column)
        {
            if (row.Cell(column).Value != null)
            {
                return row.Cell(column).Value;
            }
            else if (!string.IsNullOrWhiteSpace(row.Cell(column).ValueCached))
            {
                return row.Cell(column).ValueCached;
            }
            else
            {
                return null;
            }
        }
    }
}
