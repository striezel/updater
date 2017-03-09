/*
    updater, command line interface
    Copyright (C) 2016, 2017  Dirk Stolle

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;
using System.Xml.Serialization;

namespace updater_cli.io
{
    /// <summary>
    /// reads a list of T from an XML file
    /// </summary>
    public class GenericXmlSerializer<T> where T: new()
    {
        /// <summary>
        /// NLog.Logger for GenericXmlSerializer class
        /// </summary>
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(GenericXmlSerializer<T>).FullName);


        /// <summary>
        /// constructor
        /// </summary>
        /// <param name="_rootElementName">name of the root element</param>
        public GenericXmlSerializer(string _rootElementName)
        {
            if (string.IsNullOrWhiteSpace(_rootElementName))
            {
                throw new ArgumentException("Root element name is invalid. Is must not be null or empty.", "_rootElementName");
            }
            rootElementName = _rootElementName;
            //get data element name as XmlRootAttribute name from type T
            T tmp = new T();
            XmlRootAttribute rootElemAttr = Attribute.GetCustomAttribute(tmp.GetType(), typeof(XmlRootAttribute)) as XmlRootAttribute;
            if (null == rootElemAttr)
                throw new ArgumentNullException("XmlRootAttribute");
            if (!string.IsNullOrWhiteSpace(rootElemAttr.ElementName))
                dataElementName = rootElemAttr.ElementName;
            else
                throw new ArgumentNullException("XmlRootAttribute.ElementName");
            //Root element and data element should not have the same name.
            if (rootElementName == dataElementName)
                throw new ArgumentException("Root element and data element must not have the same name.");
        }


        /// <summary>
        /// saves the T elements to an XML file
        /// </summary>
        /// <param name="fileName">path of the XML file</param>
        /// <param name="data">collection of T elements that will be saved</param>
        /// <returns>Returns true, if the write operation was successful.
        /// Returns false, if the write operation failed.</returns>
        public bool saveToXml(string fileName, IEnumerable<T> data)
        {
            //Null, empty or whitespace strings are not a valid file name.
            if (string.IsNullOrWhiteSpace(fileName))
                return false;

            XmlWriter writer = null;
            System.IO.StreamWriter stream = null;
            try
            {
                XmlWriterSettings settings = new XmlWriterSettings();
                settings.Encoding = Encoding.UTF8;
                //indentation
                settings.Indent = true;
                stream = new System.IO.StreamWriter(fileName, false, Encoding.UTF8);
                writer = XmlWriter.Create(stream, settings);
            }
            catch (Exception ex)
            {
                //Something bad happened here. Time to exit.
                logger.Error("Error while creating XML file: " + ex.Message);
                return false;
            }

            //write start element
            try
            {
                writer.WriteStartElement(rootElementName);
            }
            catch (Exception ex)
            {
                logger.Error("Error while writing to XML file: " + ex.Message);
                writer.Close();
                writer = null;
                return false;
            }

            //create serializer and write elements
            XmlSerializer serializerGeneral = new XmlSerializer(typeof(T));
            foreach (var elem in data)
            {
                try
                {
                    serializerGeneral.Serialize(writer, elem);
                }
                catch (Exception ex)
                {
                    logger.Error("Error while serializing data element to XML: " + ex.Message);
                    writer.Close();
                    writer = null;
                    return false;
                } ///try-catch
            } //foreach

            bool success = false;
            try
            {
                writer.WriteEndElement();
                success = true;
            }
            catch (Exception ex)
            {
                logger.Error("Error while writing end element to XML: " + ex.Message);
                success = false;
            }
            writer.Close();
            writer = null;
            stream.Close();
            stream.Dispose();
            stream = null;
            return success;
        }


        /// <summary>
        /// tries to read T elements from an XML file
        /// </summary>
        /// <param name="filename">path of the XML file</param>
        /// <param name="data">collection that will be used to save the elements that were read from the XML file</param>
        /// <returns>Returns true, if the read operation was successful.
        /// Returns false, if the read operation failed.</returns>
        /// <remarks>This method uses a List of T instead of a IEnumerable of T,
        /// because IEnumerable provides no interface to add elements.</remarks>
        public bool loadFromXml(string fileName, ref List<T> data)
        {
            //Null, empty or whitespace strings are not a valid file name.
            if (string.IsNullOrWhiteSpace(fileName))
                return false;
            //File has to exist, because we want to read from it.
            if (!System.IO.File.Exists(fileName))
                return false;

            data = new List<T>();

            XmlReader reader = null;
            System.IO.StreamReader stream = null;
            try
            {
                stream = new System.IO.StreamReader(fileName, Encoding.UTF8, false);
                reader = XmlReader.Create(stream);
            }
            catch (Exception ex)
            {
                //Something bad happened here. Time to exit.
                logger.Error("Error while opening XML file: " + ex.Message);
                return false;
            }

            XmlSerializer serializerGeneral = new XmlSerializer(typeof(T));
            try
            {
                reader.ReadStartElement(rootElementName);
            }
            catch (Exception ex)
            {
                logger.Error("Error while reading start element from XML: " + ex.Message);
                reader.Close();
                reader = null;
                return false;
            }

            while (reader.Read())
            {
                if ((reader.Name == dataElementName) && (reader.NodeType == XmlNodeType.Element))
                {
                    object obj = serializerGeneral.Deserialize(reader);
                    if (obj.GetType() == typeof(T))
                    {
                        data.Add((T)obj);
                    }
                    else
                    {
                        //wrong object type
                        reader.Close();
                        reader = null;
                        obj = null;
                        return false;
                    } //else
                } //if
                else if (reader.Name == rootElementName && reader.NodeType == XmlNodeType.EndElement)
                {
                    break;
                }
                else
                {
                    return false;
                }
            } //while
            //read the end element
            bool success = false;
            try
            {
                reader.ReadEndElement();
                success = true;
            }
            catch (Exception ex)
            {
                logger.Error("Error while reading end element from XML: " + ex.Message);
                success = false;
            }
            reader.Close();
            reader = null;
            stream.Close();
            stream.Dispose();
            stream = null;
            return success;
        }


        /// <summary>
        /// name of the root element in the XML file
        /// </summary>
        private string rootElementName;


        /// <summary>
        /// name of the data element in the XML file
        /// </summary>
        private string dataElementName;
    } //class
} //namespace
