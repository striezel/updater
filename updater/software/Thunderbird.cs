/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021  Dirk Stolle

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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Manages updates for Thunderbird.
    /// </summary>
    public class Thunderbird : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for Thunderbird class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Thunderbird).FullName);

        
        /// <summary>
        /// publisher of the signed binaries
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2024, 6, 20, 0, 0, 0, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Thunderbird software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Thunderbird(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 32 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/91.5.0/SHA512SUMS
            return new Dictionary<string, string>(65)
            {
                { "af", "1e675d97dd8b4a0a7a069008f22f62040263fe6e5f6d9fcd193d3033c22627febd86dfd4cd1938cebda7f93646ef222916549a947187ed6a533c59cbbb621f00" },
                { "ar", "810fd62924e052c1d8b06992491076004884d4279f51987ec7dc15bea9b80cec6bc22ef5711c3e6456f778653c52781aac23f685a0a5153a72d99a7f5111c20c" },
                { "ast", "0d50d194de76020ff87e1b2635c94c9562ef21d46f3686080d75d5e20331d90d0091badf4666cc54635670cd9289bbd2a80f96cd9d73b227509b8f0c03dfc7a7" },
                { "be", "165fdbc8890051c9a248c8b75c5dfaaa63b9143b2de0ff9554546865ae83f130095d97241c00700351016e56f384a1364246c7d8cd0ee019c1fdf6cf2612963a" },
                { "bg", "f2f0af0d73e1e17eb076f493170a9fb1048ee8cbcd849238b354d1374c4bd1f5835e04fdd4c19da441486b4d5929e6c5daba9fbe47182900ee256cc3beef9e41" },
                { "br", "3486de5a2e6fe0c8e514fa2586a39526c01db59ed11c0505e7cc8a359ffdb2d24a14a8ce1bd89ae7a04d6277d5f839419396ebd8e237dcd8bfa333db83283365" },
                { "ca", "56e88ca5284733697580fad12f3808d491021ef8389b5ff93a007a3beedc5cea7177d18f0b5105f045150580b69efab5182833e59701aacef07d8892f0a6d1bd" },
                { "cak", "3939344cc3ea5538ce2100d7c2d2161d9fe345fdaf5f141cfcfac832733c794835fded9fc8186c766f016e30eaebedcb396fcefb08068ee84cb052536d2cd369" },
                { "cs", "e3e3036c376423bbe93504f44c9a202f84da87f23add9c850f032ca866fe5582c6be5ddd7a5f872d992ef6ecff1b806bfd7a6298bde3d8ee274bc7f62fdbe5be" },
                { "cy", "5a6bc68ebcea2cad3fcc4780ce83c58d6f9705b24a09d7a37a75e89860f02ab74d8fc93b80657d592f0a711a6598c906e5c0067626367e50dd128989e5130d7a" },
                { "da", "5dba0d5ca658ae8a472561b75ebd4432df3a54cdd60227290a87a184aca5abc5c68c4017cd118cb3a7d5ff3e092afb55ee4d5136739125c4c3e6e690cdd4aa4d" },
                { "de", "a1d0fd11039c23039920b363c9c7573b955404f89273bf8b76b3f359ca2e85b50bfc2f57739fdf359d0c099c1227ed6a871fda7512ff28152a7de90b055eb352" },
                { "dsb", "bcc6885768cceb5ddb80de075c99e701a0b154ec9e64e2d3226770e9ae18c2a4ef57e54de18799417bda8dd222179c60acf1cd74355e60bac96e711ab35a3ecf" },
                { "el", "6b89f9595035864da55c32e6539db4f0a0c41c0365d526259bf85b31193947ebffbdc608f8c1d0155ce6feb85ad274df71ba660e22ac967bdd5c163885d716a2" },
                { "en-CA", "c472d3a26317c2b8bbf761b3ff364c1ba003091e0468a3f03bb2aef8dc8eb60de91c7973292a01aea9cf4b9044649f289639d845ec9d80f7ba1f4e9ddf53f894" },
                { "en-GB", "037661f43067c08d47f7b1dd7dadef75c6f7ac6a0104aa75bc016ad1f38c304f8cc0704e5e06a37bfb9f3caf57dad9c9e803fd121bb0ed4aff764e828351adc7" },
                { "en-US", "467ce56d640ac72f24a165978fe002be94eeb17c9077aa75d0f59c95563baec220bfda0821beb140633947955b5f691172b7f3042c303b78f9763890d5b7be4f" },
                { "es-AR", "e694ec3c1f90ed3aed346a87772b3453806d98ac98a9a44efe76caa0708fda887b564f2e9eb4ef8289ae0002a3e6d0737e982daa74cd7cc0792915a2a14cf8c9" },
                { "es-ES", "21b41cc2b7c94908c94dcb384c548e79e2722dc1ca63772be5bbd1b5b2caa08a9d03ba9b9f2e3367ee08b91fb084e42e51f972fae4261857ec9dff44f8217d9d" },
                { "et", "e5c1f7cba38a6b8cbe0b878094892ad7bdf2337d1dde8c0ccefddabb514598a438301b1eec1e68d9eb0308a11df83121f8b726e632a3943a5d4f1d2f9000894c" },
                { "eu", "482f825c8fae5282c5c17c0da4772caa7018fd947e717321ef7f3a73799db8086ad655b8f605d576c0968bdd6d4f4cfcba21e8844532051b94fd1c0bd2609fbf" },
                { "fi", "255ac8305f72f45d4d35927eef99b033ac673b875384807610c4092ba979b56fe453d4c672fe4776abc061906da3ba37aec74bace4266317fdf9edadb9942d88" },
                { "fr", "c780f4142073cb3854f6c419e7262e5c380c8fcfd3db0ba46bf8b0ccbd4cba9b4b74681c5291560848c052d7e46b893ed9cf024531a7da1a76022cb5989bc578" },
                { "fy-NL", "6663e5b255cedb8f9e8c5340efe74a6b359168415d63d08ad5f7c5130c121ad68772442b77b2a73527b80c0aa000553018559591fb6a76433d5a70f3b3a074b6" },
                { "ga-IE", "1c985a3741beda60f167ae0d1b88658ff23fff0321946907a3eb4c6dbb4346bb428fe4e55968fee7af98793212a73d8aec5d8b76a71bc79f29b33b52bfb953c7" },
                { "gd", "30aae26f85db3044cd9a07cfc96b86a58fb21e0475cb99131a393c342aada906d1bf4d79535fe0d61c2b43514cbf1c4c6a214b3943907ecdabcb31aca74a04e4" },
                { "gl", "c81d9d9f01cbd6a785f4f8654b8f099249db6819513fd793b22195b51bf69364657c041aed7402fd70df19b93324e0d95c6e9b2a15345b8e13473fb2c2baa1c6" },
                { "he", "20d612c92df3fe94c40f1de85516dc3f01a359ddf62c466e446af0116cab9b8da130a9eca35c31e5f0ba3682e465ea365a1b764d2c33d3a74f210c29449b2339" },
                { "hr", "b9edb22658d474d8c94088d8970236480408fb171cd17667117306c33c6fc4fcfabd9fdfa99cbea20d6dcd51f12ba9b4ef97efeb97f97705a487a396678512c4" },
                { "hsb", "d60f13c98c6b68ba817fdf5d46af2c900ec2326c3d169b92286e9e21e9473429532ba78a2a112a64e5eca167e467d2f7773a2784782ab5a2e7000a31030a6ba2" },
                { "hu", "bdb1ee902c85af42750f0469449addc2d7f391de864a7ea92a49335e5dda2a2c22df0f9015bafc9a97dfc1ef3bb3584ac02b7f2db43ec154f57bba36de0b8773" },
                { "hy-AM", "574acd0e51b7cb180f63eee6d0eb991613d425895d2b2531acad9058137ce003eb4584700889f6d321bfcbc27e9a2dde41b6900af6bff88032b68a8e494648dd" },
                { "id", "dcfed2cc8775fd7b5e83b748ab812bc014a90bafd23864150c0c71a37f3b8ec5a7925ddc63d90f346c17641143dee1d6b867ce0d2dcdb572628e7165b4c2e203" },
                { "is", "0ccb43604aa07763c9f54743ffcd077f6f81924323c490a16400fe087ee38bc5a9e116833b5fe3aa6997319d1a7d32afee6be82ac34dd22d239d1e677e608c46" },
                { "it", "d3308e434539c7bc6fbfb64898688b13a72bfc2c91febe7345a498d7941aba8f75bb0c92f2cf502723f8fd2a0bcb5769371d4088429e531f84fb983fb7651028" },
                { "ja", "9bfae5a1c56e469cd5119ef979049a72e4ace0f2bfedffec561be19ae894159f7099f64bbddbad7fa5526403366f52554f55c5957d5e826d54563e1a6a5b6739" },
                { "ka", "732535630f3765760efeec46c82e3e69cb4962e446244788ee55385379416577a5f5008aeef73d63a787b48641f97f4c83286f78d80eb738bc3be436b8964f93" },
                { "kab", "ed33a7b87d42f8f0e6e42098dcab4706f471554243213ad5715312c10cc01e2a91a301db9653c60ec11b785d99d2bf5647920063e577d83f65e4a01cb3097aa6" },
                { "kk", "5fbeeb5215ef86f348afc6b1a10676573934064bbed4a9e54590547dcd3f48d1f330a05d38cc0042ba79fb18eda770e803eee6acd35fce88d9df0208070d6a5f" },
                { "ko", "55f796cca065c09668ce256bce131c208d2b90aa0e6185eb647711c86944f336c9e65446b93e24faf2e89d1f7662f326a7f5738c0111358abb9d32fc298d4e39" },
                { "lt", "e89a0491b607b27d8c8b91b1e2cc789ced87bc58de83d1448cefa22f3d74027d46084b8d4475887933def6704d2de3c90c0266af711c3e448a38bdc3618624ec" },
                { "lv", "8e76cb08d2426b8a853d5d0f1d56126c27c7da596d44c58b05bae5751ab3e0394650dc5a1ab048a0a41b6a87888f6560fc33cf78b344d46ee6a05ec6621e6000" },
                { "ms", "9f5afffb9de070703196d026c455177387ab55e864ca09afcbbe9ffa034ff2a2e982be0ffa52e6ccb52481561b72fea81352f20557fc2aa976ef034c04261c80" },
                { "nb-NO", "0525887d94c694ccbb738da5d4de4ee23afa56432ca724bb4e145f222bcf34e63ad18edc1cb25aa1f1d5efd9ef8f64147a4ef171205039b1be0e26538e358f85" },
                { "nl", "f00bdc36c8a9a7f5e91317642266659e4304cb938fb7dad163aec680b64a4642798189458a204b3c483cf3394adae5c5c8ee0d6149bef480368840da00cae28e" },
                { "nn-NO", "a2184fe6c8fa0fb74a0e113ce0b64eca5e512ec0684c2fa9f8e706d8659b65009205e24fd76d3df7232884b3881079c3e1562c7bb05f100fe35453ef224f22ff" },
                { "pa-IN", "336bbb949a8bc1a55196db00fd213a13393cb5cd8840c39e3c5cf1bc460891034e10e43d4ece43737e33d1a17b0eebe9ed7c3db6f46eb75085abf1047b3722ed" },
                { "pl", "31de6c2d2594c7cf94c8997be7ec0ff1144412b7505e986b821846db7b35144a93c37488954d9521f8a3a73b678de1bc4c2412e5eb26747ee16fb250337987a1" },
                { "pt-BR", "88c315185d3eefc225538c03e07178f7e0a6253d25bdc2b84dcc8ed9992cb42b8aaa0c7e62357c6bf2b74666961247b38e111414e9dc516d8e66bd49e8885840" },
                { "pt-PT", "a914493f51ef25b72774a44f348cfa261a331046168a6e9a27bed9599628544720712eb8e356660fbea9198a3400336a88a64bfd57c204bf77ae0405ee7f18b3" },
                { "rm", "afdcf296c8f434b481b75e3d2dc05bdb09d524f8b21a391637d237f3aadac33cfb49dd687abc83ad3f5100c0cbb60f9d9a7a9ea27c86392095b9e68c3a210413" },
                { "ro", "5594d2741657aaf9747fee834258eaa53714a83362e39ecc04cad44ec593f880f4236d53685139c58f69a76687c43e7ad4d8f1c8ca89ddf551ec68545c3afeab" },
                { "ru", "72704ea0a574a16c8cd98eecd0bb0a085da88028f11fb64c73fc2c5714ae2d3c3abbcc646be4e36f7a7705a3fa83e4ea200f2bb957232b8ed629440efb242346" },
                { "sk", "584c210ed2c1305a6d8387480bb2e1831b1eb25d88459636277ccc8b3789c8c2a2f7bb7337b7d10061cd2894cf326f41191286f0548f876194f7b855069bc77d" },
                { "sl", "d75fb5fa21217e552bed9bbe5f195e417aed9d8a25b4327010678afecde0045870f5046db1681233e4959db1d8688a2433c16ec8919f38a36abdb387b75a23b3" },
                { "sq", "e8101d8d817616f3f62a490be6d3b5668238aa8900ed31275d27f578fcf515f2587cb5e5f67d1e8a4b84ea85f75f3bf33a927491f20aba1f763d10eb3dc49522" },
                { "sr", "446710cfda0f9386a4fb49fbbadce33f84edd5696fd442f11d8c20ea2f7f143190179e338be8d5b82ce42f327c8c91ed057e12057c649c8a227f0fc0c24a8a6e" },
                { "sv-SE", "f09a1b0bf0bb0275402ebd480d441da0d2fdd6435261e11036debd71ebd59f5641830bb73f5a25c460fe85f6fbc57b7839024dc7430e369eec8ce729cc3c8e02" },
                { "th", "a12370ed6677970f9540036fb2f731ffde2a0e6fe4844d172a3dbd0fcd0213eabf010aa112d492e5113431686b252e7bee34164fe61a904a622a7297b25c8d89" },
                { "tr", "4a4fea83e099c57c9fe544b06ba10161e91e51f762a58630a0831e8726798520a634c506836b60d627619e689a338315f16887cf990599ef7b300d460f7092aa" },
                { "uk", "629674ab867ab2d1dce091397863181a5fc27554ee62ba1d4af0439019316059b1c0276d1ee1f8c36d9729bad144a2ab103a21338816d8d7592886c043d9f0d0" },
                { "uz", "4a17a78efff7d24a4cd7284371976466a8381fbb39acb61f1f6763982d5fdc4ba3c22b4ca232568bb1a60899c3336f86621bf93128f33a9cdadfda6c7a4e3ec3" },
                { "vi", "345a198690ed6b1addaf1b744b591705a53ae49f8e08d3acbac45e91706f784b2a3c0974fd7d6f30539dde57c4951181fb2da284e8a13b6a0a585fedbded6d32" },
                { "zh-CN", "5c7691727c85934597108a4b848c21baebb9d4a5c49344cc8a0171fe893c3b3e9ac5df114503d47cb8be223afa6e716994252e49c1d66e52e31982fe80c9dd86" },
                { "zh-TW", "506808c7b5428da6030f7bf95eebbd442561fb015bfde163db561efd54a150bc80828f2ed59f0f0ecaa363d928f4788bee0bc63db53a6a0ccd9a9e67e8711ba4" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/91.5.0/SHA512SUMS
            return new Dictionary<string, string>(65)
            {
                { "af", "02ad67bf9c81e58a69e7932af33717acaa0455ff6d55f4267c01ad7f8c5985173faee0ddf17ed4051ab6282d15a9ddbcf652f0acd4eb59473d9cb1a1f929030d" },
                { "ar", "3c639adf243c19f289f770f6e122ade48e6a7854ed233632af51929c429d4cc0e76eae74b6c31c7b5dfca155144485d880632d31f1fcf61bf2e3e0fce5180231" },
                { "ast", "65c9989a85f9b1cc8c322e7627a5c573fa5407e8efd78c3a5e307768c799df39bc820dc56bfe2ac1c2af80fc313f322b3833d5625a2c4ce4a92eac2145b6a0cb" },
                { "be", "67f59b26ce34db4e9baea73ee3653ff51d8704b9edc1ec67999daee191cde958cdcdf641f1c27e1623e5b614f58f7b02b9b246f048536954eff51497a8cad9a3" },
                { "bg", "ce12fb9cae957b56807f38762e2b5bb472d69635085ef01299f063ca2fa02b429fe693e2caacd060fb7c8020714360a263f36e53801a6d5626f88ea3088df3c5" },
                { "br", "1739dc50c0eb3a3c8792037911bb97f690b7605006bf997b6113ab1816263585662618e8b8718a46bdf381da28f7a427d72dcab9382ff6a0e7f6181f2480e69d" },
                { "ca", "f4cc75f27257057690e4fb121cdc65d26309ac12b5cc65475ee63c6a1ff7262d7a9e30b1e458f10d0822fd77b8ab864570559f5f466507cf5c4723a8121fe7b1" },
                { "cak", "014bd50c259e82b791448c45b70be2514dff080a165702737084fc725f379da266c8208566fb0be5259fd2de8524d70629398beb4847dbcfff07a566f5f28ae7" },
                { "cs", "22bf9b11e12775949cf314d030b4f3b3fa533218f342b6ab7e04f3b2a4a366758f37b6d98f485ac1b749ea2c33fbb4347d66245b12fb33d289c059a1c5f73e0a" },
                { "cy", "cd30fe38cf713f864aefcfb162da5330152c2488b94e8cf4730de38e3ee4f7a45264d25007d26ed9829bd1b0564d10375807e52a5864610ac812de1ed37be6be" },
                { "da", "9aa3f606fed34043c8c2753e77cec0cfc1d28bebf9b1568c3b5beafe0d975e41417ff0cdb1c639caf8f041deb527a9d7b1c9fc3968ddb33c2638746312d5d6c0" },
                { "de", "12f07db926a1822fb801d8ec6cced3ede944eace46414b6d3344e543b6ca5b258b44e09b085a5e95a44430cdbae6444525db583efd26aa7da3136af138e8d2e9" },
                { "dsb", "a454bb879ddbc1d6327cfac7149c4d50ea1e2d8364b5fb060e88337d8bb834226fb343ca2d97bed3d019e688d2421df76310c33a7fccfd0c05e547346edc4cdb" },
                { "el", "a1516dbbdd4d4a83c96403345794fe1ecdaed7dbae7d0f687c6fa681bcdb5fe8b59f8c63c78d7420f574fc24bee0bd782109fd03f9c0188f7f3fe39058d88fc3" },
                { "en-CA", "369252addfe6eac24ceeafc8291c583359a590f208979797ff8f51b14838c125cc2e132b0844bcfdec9d8ba989119bbdf49b68d78cb01e3bd9d9cc4435273a37" },
                { "en-GB", "8a9ab8ef3b75541920a4cc49c6ba528a2fabe24fdc107348fecbc8369036462d9a079f0496bc960e794e63f4ecf34fc65231826456d192e5c68d7439ca75de47" },
                { "en-US", "de08d0e9442b89e88c93b0162bf723085c18fe900cfbf55675563e66447549a88915a4b244b5e95174ba69bf13de76a0341b7272cb0f67de7ea82fa81997b3c3" },
                { "es-AR", "a80031daaafd2a81f0e439e7579965b7122d99597935b3614d5530735878d9b0aeafebd3e53da50e9cce851c717f8d4e4a5105636c89b343d188e9b5b81ccf6e" },
                { "es-ES", "7aab3f2fc210dca95ace8124aaddfb71c9d858e30b2a974a776e33a6e7cbb3f02b02fb2559317aecf302364ef851f31ba3e0bfe6df23885307a4d1b0f0fe5d35" },
                { "et", "1e705142a897aabc4f9123cb4a3274db89ad5ab84ca66f823aa75b41592ae66ffdee1119eaa5ccafbaee8be31fc101cfc97f3b8563c598bf643791dd28ce07a7" },
                { "eu", "d989400cf682c3eae39ac1676f77cb37ae5bd7f80f7e74ed426e4e33eb6b78309548826304c0660211c1ae79e99636ff5fc6f2e60453ac35facc39b4c21bf9a4" },
                { "fi", "840bd4e4db51579350aae54fd96d6aef72027df677f033e48d630a56b282ffd638a743e51c7ad566ed3819a062780e5bc5fa36deb54ae4bb65c35a77641dbf8b" },
                { "fr", "40748bd35ab8c08e72d6353d2b48f736c36c205f4e5925bb4b7bea468a074e5584317491dacacf21b87e4a1bdf3229f528c94ed61cf57b6451f3a6f9056f19c5" },
                { "fy-NL", "0df81ebeb0005222741a56fc4979205e6a8f5098c892c9a8815535e1d5e4c46fd50f0a2350fbc3e92c5ea6f4df05ad35395a1d6cd65ab4961b9ffa076aeb4dc9" },
                { "ga-IE", "167481452408d1dc64f9ce735e39fbd6a1fbcd0d7d7760a2f6b62037df767852bdbd8f2f3908ba83550fb098d2f51e49bc95b73079fff3b6a80e1d6b0aca2d94" },
                { "gd", "5c754f3e444e1ef811eb2a7802ad2eeedd86f8ca178684c076835c9255e4224442363ff914872e5b589da5deada9662c7ab7ad61b36109347d12511ea3260311" },
                { "gl", "3553b0cc9bfe9c641d80f5d6361c9791ac558625964d69f5eca9b46c9cbb8f369cbf646467ed6353b8073a31896ea70aa57204d66b36ddfbe389ab7d25f1496b" },
                { "he", "13dc053e410a36ab23e030399dbef3890a329f1c283ac08033a98e0fe5558cfc106afff03aa463625795746201505981d0402950a661e171934333b14f1e5795" },
                { "hr", "64dca95c92cd751e0d71f594f042f4f40fc0b24b8e0155ffaa2f161ff842a95991c5b87ba0e6507dabec42a6c305bf2e149c0e5e02e02be162d9feca03ed4d77" },
                { "hsb", "7ceea0035032a8a4cd76e7c83ade4d8acbb8cb6921194536a0b882ba55c1fa5aa38ca0de808d30e5a3b97f983b65769486260591e716af94b17c39fe667b62e1" },
                { "hu", "e8177e02b06b1256df3ed154b6b6436d7e69d6f2ce7f1c21ac838d3bb5660bf08a207f1a046c74641489df93e41f33fef0f14c4cda2450c032a14bb89d2748e4" },
                { "hy-AM", "2208d918c5f0d183cb02e3d17752b0b48bf6ddcee35eae4b39f8179a606264b96a451d5c50c538b2baa613724664d7b94978d87a54588d5365de2a81f623d052" },
                { "id", "030c6ad0baff8f33d000e32053b5ea7239ff2bb230cee5e98c7a1cb21e24f266a5405a7f1d8641ff90d50d2eece8541649686823a96b14dacfa095aaaed6eaaa" },
                { "is", "25a2574a34a5c053a534610ac1b5e14fee4a33b235756eda53a39f5a2c31853a48ba8438bddfcb32a864402d5738b98b65a3e12016976a717572be1ed23ea19b" },
                { "it", "e3048709f986feba651c7958946313232c8486420ba4db518c90c9bcf883d44614af805ada9457af2e3e3bf34bfefb95fef5eb4f7fb28a8f5019ccf596d5f2ed" },
                { "ja", "ca8cb8e605093edffcdafc20f76f4c4a1fd9fb493246ae4d5911d38a922999ed336069366a56d3bd19a89fd4f9f0caebe923e3a19d27b3361fe567923b64ea62" },
                { "ka", "1154edf2c1fd459234979568f4bffaf50a8fe0d087f34daff6cc53bdf104cb7d6c3efc225ddae7f0486b45a442705492fc66e73bf4fc7b9fd21fd2a39002b89a" },
                { "kab", "611d6b926ebd807ca1066ee011e2085dbe5bd90d97c3ccff029960d41ffa4db12f6475bd4fdcfe643da6cd567f0a9ec92489095b901d694df8195c9bfc93097f" },
                { "kk", "a3cb67c8b6d7e92b7d52fc37c18ad788089ba96499560bf7315d226c0aa2efc0801485f5a716e42004eaf1f0d18e292d4185c15cd0b5ddf4bf6843005fba8106" },
                { "ko", "4e582b77de680fe13a4fc0044dee9a1ba066c62f2b5ab8b0ae1ce14a028541e8542488ea406cb28a7f9be64667ec1f01fd54195f50b9c0a8e72a5d32f4659059" },
                { "lt", "f86807bdf2f3577287cbf8ea70e65387320ebc589fb69ebd22a320ac96dc125de442a1268c02dd5d346a3879bb582d57e2f28111368e6d12b5c5eca7dc2f5183" },
                { "lv", "115a15811afa8138d0cf9bf4e9e7ffd32b3f7f971e7c64d3558e7e35ad63091a722e8015df490ac2730d5ff32dba01437179eae5a4d60c6b7a31eac8339a5d11" },
                { "ms", "691397f49d544a9ecc6003716041e705c3a1277d89d9a1c8e8d96b19da20cb01337fcba9dacbcc631c235b765ce0b60fa7e2e3ca44558f16160f9d4294041ddd" },
                { "nb-NO", "648acb5d3caf7676565af55732e12e28b00e09c0e4f8c7e4b8971d31af34c54e730134b82057be2b902cc2aa322124529e865f4d87f95aff29dcce0b0ea97039" },
                { "nl", "07b0de150d78d5bbda4c684e1e6be5a1ff25bde54a1bbb6bf0a35cede422917be9cf69f697a5a1ed158edfa3ca9bc9e2f3c16d836e011b7576eb0a373b39f21f" },
                { "nn-NO", "00005d8b47d9285fbae89582eb4c8f3a8bac0d97f13ee301c15eae668aaab0f187465291d85a888837a45bc29b6b7a8b61e911f4d262345b2b2caf9a107ed945" },
                { "pa-IN", "301d8234a816884e36239d16a6e2ccc5f06f2497272ce3e508e515dced0358d02598139c39d7e7b5fe20f02ffa69e084d9194c486df4b655fde7c98a8195d5f4" },
                { "pl", "a96b4b5c25166039ec0743df325aec854781fa46da725d90b4459b29cba0a663dc0345df77610727a8a3a1b7e35b707d4a564c709e4146c5bee715cfd4761c0d" },
                { "pt-BR", "19eb4c3929110517fa1e585a502a04aed55ef5efdb636f349241c7f362d0c53a9fcaa5d565120dcd338599ca31b98296ebd6af958e129185e189ee4c7c810873" },
                { "pt-PT", "e61835e59e22c8d1951bf1dad03585ae641863df33ec1f508d5ca781cc9eb540b9f5ad70a74f9ec51aa4ccc1bf891d5ef53f59851154ae3294e50188f9806e61" },
                { "rm", "c0948fc0c990c7c539075d745ad3bce7595a6dd98393722e0b437d45dda29ad4b4e86cc1b1f80de87aa442e38d6224753cf467a0a0daeff7b564a54b8b111243" },
                { "ro", "a0f43f3c69230c2a5d4c25bc5b96703240f4938c7dc5bd3582358b0105871b4410d8759a3c43779f891e527e63ebe21ed00d682f4835e9e9132ec8abb9098306" },
                { "ru", "7a0e20a57c9ca88e81cbf20f71be9d481f46a5d73c3a3d8c3f83ccb3118ac6b321323c1c20726a15e3edeb0c3a69183d8ede1cf4c4ec755b1e941bb8cfa9a993" },
                { "sk", "14fb50cd2d748b0ce0419b124b0cbaa3a8803c711956688d999214c891478b262d8904887b3c0e431235826452e0e77b8f9a987954830c7641569229e28320fc" },
                { "sl", "82e222a8469a3d506bc3991dc960e55e6d72f8fd6551d0ad2dae26d815ce2aba474f4ae7768243c6efabb7da7cd4dcdd197290024d2f2436fe3e1f57eda829e9" },
                { "sq", "6f48693a13085f740ffad6060f96a1bf605435d8300c029092859d16061282ca28bd63add29c2a4ddbb455b505be5f7895ef7c924bbff08cc5e41bac7d33fa03" },
                { "sr", "5abce54b91564f9b56635436adf6f55e130b6b58f988fe6a8b4c412692cb8d5b955c07fe9f927a5b657c76daca1add359d7750320278bf4da856a9de30d18aee" },
                { "sv-SE", "bb7ffa3102b88fea5b459750f18cb63835d5e8c7daa8cde2a4a53501a1d2dde1a13f6cf652d75f4ec5a4845aa17154af4a069113afacb9b46d387231f06bb745" },
                { "th", "2f1c7d191e71a14253e66ab4cffdd3ad14cd0796b4811e03dd2d924ee917d25ace2118265b572275384df87fecbf51a2d27ec02a95a65245b534424d96212bd6" },
                { "tr", "76d8a3fb3a10e5b78ada5210f91f342796997c58ac08f0af8e3653411843c760b1dff4f172deea5d6395fa6f796a294b8fef32c5c6a410f86576b824b959847c" },
                { "uk", "22daaf5b3aec6abf2755548821b6f91869d636431f43f566139ea4906d9b903a05bc2c18df498492d1cfae1b6827e5a989b7c6fa627b3a1fc3e4da561a7005ea" },
                { "uz", "ef1b4144b991ebaf7b51fa64e6de5485cacd35d8dbf4144d05f0194eb6adc55c0a9cb228a95dfee6ccd35e5843865e14a79ac5b4d275235ffc708411f8224656" },
                { "vi", "62143a4f624ded6a5479aca0e182ccdb8732c3e1165767772291a84c79f3b8ac410abee764e3f56bd498fd6cc61a7c7aeab105dd9390099e4d8541d31a945ee7" },
                { "zh-CN", "497b3d6da1d771f626801a20dbfa37450f99123ee461969482367983b8355085c33f15c92eed6766ae42f9ffa2a968ae90a70dff506f6a31ace34f1d07246816" },
                { "zh-TW", "96ddebb81d2d8457faba0f9129eb85b25f4c130c41718cf0228eb1e91c77d16a79c0c2f57a34b35ddc3d8a55b974079c8b6d3b0697f07248d872a65283378f06" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            var d = knownChecksums32Bit();
            return d.Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            const string version = "91.5.0";
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                version,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win32/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win64/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma"));
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "thunderbird-" + languageCode.ToLower(), "thunderbird" };
        }


        /// <summary>
        /// Tries to find the newest version number of Thunderbird.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=thunderbird-latest&os=win&lang=" + languageCode;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            request.Timeout = 30000; // 30_000 ms / 30 seconds
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
                Regex reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;
                
                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Thunderbird version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksum of the newer version.
        /// </summary>
        /// <returns>Returns a string containing the checksum, if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/thunderbird/releases/78.7.1/SHA512SUMS
             * Common lines look like
             * "69d11924...7eff  win32/en-GB/Thunderbird Setup 45.7.1.exe"
             * for the 32 bit installer, and like
             * "1428e70c...fb3c  win64/en-GB/Thunderbird Setup 78.7.1.exe"
             * for the 64 bit installer.
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "/SHA512SUMS";
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Thunderbird: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using
            // look for line with the correct language code and version
            Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return new string[2] {
                matchChecksum32Bit.Value.Substring(0, 128),
                matchChecksum64Bit.Value.Substring(0, 128)
            };
        }


        /// <summary>
        /// Indicates whether or not the method searchForNewer() is implemented.
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        public override bool implementsSearchForNewer()
        {
            return true;
        }


        /// <summary>
        /// Looks for newer versions of the software than the currently known version.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public override AvailableSoftware searchForNewer()
        {
            logger.Info("Searching for newer version of Thunderbird (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if (null == newerChecksums || newerChecksums.Length != 2
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
                return null;
            // replace all stuff
            string oldVersion = currentInfo.newestVersion;
            currentInfo.newestVersion = newerVersion;
            currentInfo.install32Bit.downloadUrl = currentInfo.install32Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install32Bit.checksum = newerChecksums[0];
            currentInfo.install64Bit.downloadUrl = currentInfo.install64Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install64Bit.checksum = newerChecksums[1];
            return currentInfo;
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return new List<string>(1)
            {
                "thunderbird"
            };
        }


        /// <summary>
        /// Determines whether or not a separate process must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns true, if a separate process returned by
        /// preUpdateProcess() needs to run in preparation of the update.
        /// Returns false, if not. Calling preUpdateProcess() may throw an
        /// exception in the later case.</returns>
        public override bool needsPreUpdateProcess(DetectedSoftware detected)
        {
            return true;
        }


        /// <summary>
        /// Returns a process that must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a Process ready to start that should be run before
        /// the update. May return null or may throw, if needsPreUpdateProcess()
        /// returned false.</returns>
        public override List<Process> preUpdateProcess(DetectedSoftware detected)
        {
            if (string.IsNullOrWhiteSpace(detected.installPath))
                return null;
            var processes = new List<Process>();
            // Uninstall previous version to avoid having two Thunderbird entries in control panel.
            var proc = new Process();
            proc.StartInfo.FileName = Path.Combine(detected.installPath, "uninstall", "helper.exe");
            proc.StartInfo.Arguments = "/SILENT";
            processes.Add(proc);
            return processes;
        }


        /// <summary>
        /// language code for the Thunderbird version
        /// </summary>
        private readonly string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;

    } // class
} // namespace
