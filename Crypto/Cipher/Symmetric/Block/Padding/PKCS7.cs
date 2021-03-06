﻿#region Directives
using System;
#endregion

namespace VTDev.Libraries.CEXEngine.Crypto.Cipher.Symmetric.Block.Padding
{
    /// <summary>
    /// <h3>The PKCS7 Padding Scheme.</h3>
    /// <para>PKCS7 as outlined in RFC 5652<cite>RFC 5652</cite></para>
    /// </summary>
    public sealed class PKCS7 : IPadding
    {
        #region Constants
        private const string ALG_NAME = "PKCS7";
        #endregion

        #region Properties
        /// <summary>
        /// Get: Padding name
        /// </summary>
        public string Name
        {
            get { return ALG_NAME; }
        }
        #endregion

        #region Methods
        /// <summary>
        /// Add padding to input array
        /// </summary>
        /// 
        /// <param name="Input">Array to modify</param>
        /// <param name="Offset">Offset into array</param>
        /// 
        /// <returns>Length of padding</returns>
        public int AddPadding(byte[] Input, int Offset)
        {
            byte code = (byte)(Input.Length - Offset);

            while (Offset < Input.Length)
            {
                Input[Offset] = code;
                Offset++;
            }

            return code;
        }

        /// <summary>
        /// Get the length of padding in an array
        /// </summary>
        /// 
        /// <param name="Input">Padded array of bytes</param>
        /// 
        /// <returns>Length of padding</returns>
        public int GetPaddingLength(byte[] Input)
        {
            int len = Input.Length - 1;
            byte code = Input[len];

            if ((int)code > len)
                return 0;

            for (int i = len; i > 0; i--)
            {
                if (Input[i] != code)
                    return (len - i);
            }

            return 0;
        }

        /// <summary>
        /// Get the length of padding in an array
        /// </summary>
        /// 
        /// <param name="Input">Padded array of bytes</param>
        /// <param name="Offset">Offset into array</param>
        /// 
        /// <returns>Length of padding</returns>
        public int GetPaddingLength(byte[] Input, int Offset)
        {
            int len = Input.Length - (Offset + 1);
            byte code = Input[Input.Length - 1];

            if ((int)code > len)
                return 0;

            for (int i = len; i > 0; i--)
            {
                if (Input[Offset + i] != code)
                    return (len - i);
            }

            return 0;
        }
        #endregion
    }
}
