﻿/*
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
            // https://ftp.mozilla.org/pub/thunderbird/releases/91.4.1/SHA512SUMS
            return new Dictionary<string, string>(65)
            {
                { "af", "952d0940a1ce6f122d22dac0eca9147ac660724e4b1b1c555aba38605a322d09943fddf9363f9ef5298b7d431793ba68022b12648f1474f4593112d9aa41038a" },
                { "ar", "66b126afe4681a13f16f9df17ccea6fb3f00683691bc796fa986f31ba90372645115a9d4d4481942bcada3c8a799e248b92c71787d83ee9f726a323e80492017" },
                { "ast", "ad93ed6909b5f0b54dc622028a05c77b809186dd1f797f8d180db9d4530c7e52d0b1f68df388e7d48561f238f36f04f496e3426b1fbb5a087d9977221a6876a4" },
                { "be", "45342bd9820af4bb9a55fde8476c269e0d76ae4b06579409d945bf6ada02a6ffc55e6bead1e5dd349a69ea20535cf6c755fb07aeb2c6e1786c585dbac1a8a2c3" },
                { "bg", "a80266ee0bddec9bcdd44a20dded5311568d76d4e2007e6e1cc7dc8d42f1973cbbab6e66a9d50caf926bf250d4b29b2be96e3f0d76df9eef4916b4bb49998ce6" },
                { "br", "17b450b74a2297167ee00afaeb7ab8cf0eddfec30cfecc525acda627154d490d16700aa754078f7606f073ead747f12d303546a568b723add12c8936a094a411" },
                { "ca", "8fb13fceec03405c64f81cf48cdcdcddfe78c6d3eaf86691741e40450263d4bc4a15ef4616c4d21a6379a5d031fb38f92f4ffa8c6dd99bc4746dfbdfc1be8277" },
                { "cak", "acf835ea8ff951912ac9915d4dc7d5063c0cb655e80d891ea345c82a74a0d366380336fc7a80b2900ea359580a7f47c7d48c9369c295f87f55a147d322e62fbd" },
                { "cs", "e74734e60d4976369f47c95a928b9ed3b72dcb57d03bfe74e824f7f9f79f6987e70bfed1c1ea1b2f8edd75f8585bd4dcaba8638d602bd5f230b8871ec36e0b27" },
                { "cy", "937800957e7103df8b97e1f4ed5c66a97547b4477cb45c9e1c394ecfa9db5520f4fa365867d5ed3160fb3d55d49c99b22f3b26d770a2c719dcb5c2ecaf5457e1" },
                { "da", "f2b573b4da71966e2cdbe9ae4c9554a70268894ec6716d5e0aadcad764bd50980425e08dea6ed382fd69d0334b5f543ac567c4ad37350517382d246f0c9665f9" },
                { "de", "398bab09de00dcfe55f7589c81fcb450a09ded2d3c72e8eb859e7edf145132a200fdfca4ef5d243e8b81ac04f11844af9f3d9ce23d0bfcc041d02636b5c0aee9" },
                { "dsb", "da0b41b7eb6d39da78d229c2d3cbae17045da6c88ae7f74b912c165489c247f58171ab6662aa662db087a78aa23214f445ab4dcd22bc86f1de58d99b2ac63a60" },
                { "el", "7d6e35ce382aa4502cb35cb8521975c0856a43c96ab7ae99e39f019c261f0a2a5730d27efe224c9dd951483da03c5a796f5dc3efe7701791dc77b6aec582ad60" },
                { "en-CA", "206d2f32ce55ace074a97a8afed0b70bd18958392f31aaa33c0f1d57bf01297e23b9064766d3f2caf482af9c65cf68152806f26cf8db6f2864cb4091b39849f7" },
                { "en-GB", "21714995000233d1ab8595c77e4f2f15fad28d2f7589e716447019d6681291b7e56a109641931b9acaaddacaa8e327237c516169d3c06b73e29e02d0cfa4b066" },
                { "en-US", "cf215894080e4989922ec16d9229b732b30cfdebdd0a7509d23ef5a18882fca87c6a385df448c10079b314b8de87a127f734aea9e752e21abe587c907c88b042" },
                { "es-AR", "d487c6bb95bae8d9597ce007dac1331efe4c89cccf0c1c6c17aad3f392f86d300a19acea378ec00d9a79b9c675f3d1936b1ac17a3301887479e994b6463fc6c5" },
                { "es-ES", "1860a954215be43ee3e432c959e1d4bfd8c873a78766d25f1a08e092aca58dac368c8491752aadab7b8d945876e113473cc45b62b572089e36cbb7c11eabb492" },
                { "et", "3650848593ae7cf6ccaf451e1b8a455f076bfe1223b78053b406d943b7573ec014fe97ab5e0ddcefd174141a9f29fe642e635f5475c0f9081d34659c4f9c2dcd" },
                { "eu", "63f23940e0fa142e5bfe15f095d4433d9f819a7abaafeda05145048c86496a0c152772ebf796326b6784c9762d24d7cec1cadc82dc15ea06f94aa56b27e87840" },
                { "fi", "68d35a40cee85f89a0c61782f202092472bc6285e615681c4b1c42fd7a9a9b47e1e8814867ec500f0e884ff5dd2c0861f14dc44beeab17bb33659db29f72b8eb" },
                { "fr", "d1d91782c27f54b590a020bd21769a48056d0ae167df929c66f858cf358a6103a60c0c2eafe74be9d8c01dfafa98abaede822c33dcea2c94a0d4accfedf1d6fc" },
                { "fy-NL", "193563a87c647c001c627bd9ce088758005bc58f4131e46ce2a82c4708bf2dc43df4b9156fee8b2d5c1169fee8aaca9684a85c33cd52314cb1bddcae529b76c4" },
                { "ga-IE", "8f1628dfc37d87a82af4fe2833839c0f36c1dd73126119fe621acb928e1c16f3b5914bdb8563cb3165c3ac4bf8d6b1f581bcda72c7abda106ac30aaaed4e36bd" },
                { "gd", "5d44203006ab3e43af02c007baf22fc92cfb20c4300a2a07bf13357c6626ae4cdfb786db41b1e39191d1f7dca9e911964ae4862cee7f0387b544135a6690301b" },
                { "gl", "c8a4c6b1e90dd0811ef815fae5184ce3a7e2d00f8d9e8842276bdbc5335f5bb39c0b2a71273cdcf5aca4b2b7122e989ee8a1278155867d28e808fad7a8550ad9" },
                { "he", "b50cddcd657dbd63400766269b8e06038a196472aa67adb7684f76db9e9666afbba27f39b0d6b213668723d526be1a373b859f7be0b333fa6008618dc3ec6e36" },
                { "hr", "c1c85a94a28700ec9cddec0ba7d15f4900fbe371a9b6c49613fc82dba97b9a8972684cc99d0d18a352af487a4fa1d8aaee56aec071f9e13a188f313b76cd7209" },
                { "hsb", "bfa5a1dc65b52fdc63bf8c848a6cd2edae0ce71a8581fb60fd0ca8871cd90df5a2565f98ebe6a287ec86cdad08ee59a20038453cd918791e7309cc55d00f0500" },
                { "hu", "16a35fbd824ed4b9a7aaa7a6dd92d432c1d66289a4a5dd92a9667b5bbfc247039a574eaa9c8f1e84a4c29f1639c72d54a2393ff21c7f838af9e0033e1a152e0e" },
                { "hy-AM", "cf950ea73b36f93f984cdcbe8c519acd3937587f44f1df3ac9d3d3ac020c80ad21d365125919cabb95102f6815720276d5d110d315f7bd237b79873e43b646a9" },
                { "id", "e1a198b9ba9f152cdeab35761d8aa625e8d548d13a939084d0f62e4e4f27befceee475db619341d70989d1ca76e8380adc1a2b976583911b4d1079bddaf8ebb5" },
                { "is", "4969103e2b5b10e7e3f0ec772f916e0845dfdc84922d7efab354824f83c4b44119bca6dc21ed94df9e7b4afbdd8865bac717c82c29ef610529f6c677902e384f" },
                { "it", "6131db518363d5e77860aad9a68e853b3dbad8c915422dcb71f97a83a8d5520fa9d659081865b640449739891d085192b72a7300e8a72fcb1caa5f75e955b519" },
                { "ja", "36c5393a65c64ba3f1e7cfdad7eb3dd6c49b7a7130dee00f0a84c76b46c68073dda1ee24d9f14ba90869162912a15bb3809d2cb2bfc442a0c1df80a088dd7608" },
                { "ka", "eb36b1b5dd8a84ed6ab32c82a98dc426d6b4614d85675caeab1a51968690c9bc19fd66b754d005710b367c06efe57d786f991a8e9e8748cfdb454d61c37eb268" },
                { "kab", "e8f2108a09009f8843c8c5ed00befc734c8bae2abd628bbb6c3fe41a96352e8373fc6a7bcec3ce284f995ddc8b86ee879f562e1cfa02969dc34a8c775c80b5ae" },
                { "kk", "b7785684ed5dcfc4c506e48871e8162cbbc3a6d2654dee2c18a42d3a695c7c5dc600b51163075459c27f0a33f8a094cd03d55271cdebbfa9d70f550b03dedf30" },
                { "ko", "9dacf86ffde49f484f4b130273b34da05a26591548e900a0be1af74ebe50724e0ef64782dbe0f0c6b585375ea3fb2f24b96ae34348206bab2a8bf496f53f53ee" },
                { "lt", "0f8f371dde587472f7fbb0406f542e46f87b7175885902626bb7c5726bb95a933a74608299774a68c3460faf283e3a5bbdfaaaa7cdf683958f15dcb236b9df20" },
                { "lv", "1c41d23437bfefea6a7a7073563a8d2127d69ce5bdf7c7d7544ad141d0efdf90cd080c26f9b2791e2db8d114fc780ab7d9e217ee9f13f4fa14e5301f4cac0942" },
                { "ms", "460cc97a68eb5e73405415ab0b456d55c492f03272c002978489e2dadb616a69785df1ae6d19154033ff7ecac178a068249b7179916b3d91c9bca54dcf95b8cd" },
                { "nb-NO", "ae3c9e25528c50319e813116df88c4e8ad95c3a85b06606debaae290945a70fc8f8b3465e8f60a061a977bd0e19aa00e5ca56bf846cec8115f3498e2c9a0b09b" },
                { "nl", "a381d9bf40171ed5c1e390e0856af3abcba36a2e2894a06718d522194d69d91a93b210666fe64fd4d19aa7ef803f228851d231bd92e1fc4edb8187f226b64e20" },
                { "nn-NO", "49640845f7e4a5e4188a563c40ed802cb056267f94b06aa8a5191095c25055f36f37f84f0a7a11815844992f83563b9691af31403697492825c510ea8baf4ac7" },
                { "pa-IN", "c0131bfe73410b1e1c23ea74881d5ccb233376ae92e40cdce62e44b0297b3bf5fd8773aee0457dd812b5774daebb187eea5864387b7f84cf1b4d795bc63564db" },
                { "pl", "96d9a8be14252799254b96780e8e87ee534e6d3bc04d70c4abcd6439aafc901ddbe17a3e9e818965676f6cf63dd624dda779b6e765b6fdaef32242296543f34c" },
                { "pt-BR", "5d90b8b5942193ec38c83ac11aad752d5c6a7ed44e86ac6158b5c3c98f9583cc59ba2ae768605416151afc8171a5deab28eb316b0ff2b4fc2da32ad1e510a88b" },
                { "pt-PT", "eef255eac362aa2fbeab6020acccb66205e1b474ad4e0cf266bec7d6f3e9a62c1e7709ae55bed2b934759dcccc3f353fd3605fba229e4d553dc472764d663f6a" },
                { "rm", "d710aaa437378b41c291a0ef95113b05dbc59b098c3a3e3e28096db9e070d3cd2994cc1b8ca9aa81a3eaf7706b303e38dc7f1ad37787f8831eabc17b383b3d44" },
                { "ro", "cecc3489e1df7ec1e00e3d7c78ce0a598fcf1ff60b19c9382a1942db57e254fca612fba318546fa02ae7e525cb8d4296589bd00a1fc23fc8cb0dea82bfac8b4b" },
                { "ru", "9ce79a86cd1ee4bd4f8b84323d612b77384d8c4425bb0773fdd2e02023e370dcbbf5becdf76df10be26bd36d15608cce6cd99dfa84cd5d801bae026f4b62f873" },
                { "sk", "0069f143303fad5c999616c7d73227b89022f60d4c6c850c51ccdf68901546b76ecd7367c9074ef05b0fa44a48e9aa30f23e338374ada5b7209f237eb91d20f1" },
                { "sl", "1a3f45b3e8126768ea08f28c1d5a9da951abeee9844c14d9761f5a800b490f5533b36050660bc756b4d1aa490645ca226781dcc8457358735affe6e752f970a3" },
                { "sq", "758335a0443d5b93d68e39b1b2abf668020e7962e54d9a6f06ce1ffcde53d01fc71ea0d3be412c7f2d823dce2fe94c286df47e381683ed13456b60ec19f312fa" },
                { "sr", "1c7de9ae4a72c8a45b6ca340094cd3acb7c5218afa137a5d7746267c8b3a0224ec4daecfb6e3c4209368db07e57b38dd28082b6d66e221337792cad6bd4b8283" },
                { "sv-SE", "e100482445907ce24b0207c5cbb841a410b9de939705509c887d5f95faa59c53c5d54b333f7a694f4bd56742454cde2fc8b2a564e14a7b22eb5b32ec24dec2e0" },
                { "th", "67e042c6663ddbb70d20bafd52d246716812a2e4fcad5d51194e12d3454d9eeb970dacd634dcc16150572e1d4db861f61817e01d39cb1a804a5cb09641583dd8" },
                { "tr", "f2979acf81fb55a37d7780b19f873ecf37bad2a52165839fb72bab02576085696461acc91a2ac815cb00d1e72274b83a254ecae52a2e3d53660b32bcd48d872a" },
                { "uk", "5a4363550470d4006c70275b5586f81e00c28cd50aec171bf07a0d3e5c2e9cff87a08c56e91b7238e25fc708560a43b20f73ac1276c3f96f825ec3278eefb7fb" },
                { "uz", "107ec5e99f9cb333a9c5a7e6ed27b587a1bc2acb7bae00e15ed6d1ed4081586d18d12bcf262d80d531f9574277464a589f63afbe6fd147ea6a28807d52b24438" },
                { "vi", "578d5b7f371ecb7184e6cbc67f6cc474b1e11e50bd05a6db7eac3c7173c9c7b35969e42cd1ee2a61ca2f7e09b80f48fca1d9075e06af4eaa90a72814b783b337" },
                { "zh-CN", "2771567768e569f9dc2bd66cdcbc4a7258563e50f7ee99d70bce3dcdabe03f3e68512e027ef12a0731f4c382e24f8a830f29d307f6d1ecc7e3ffbb8515f6932e" },
                { "zh-TW", "49df2b89c68d3d01d7ad9fbd3603f89c90c4381635a442496875b6e8569c0d56ac016ef23148c6ac82ac51d5b850d435a28b0b5cd2f52a0da1aa3bfb42b11b20" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/91.4.1/SHA512SUMS
            return new Dictionary<string, string>(65)
            {
                { "af", "dc2011fc3fb24bd1c763fc6e042f671727fd6ab6a7c3c26f82bbe458b605f2ab9f3e4c9b408336f23743ad2be4eae52ee8e5d1d1c3058da8bf87fdbb4b060b1a" },
                { "ar", "2c9c1fac0df0f600d06ff810f24b38e1fd5d4220f58882040927556edaa070b221ce9c0828e5f775456b453d088159b3ce3ae30d8eb85915bc9aedf610db4c15" },
                { "ast", "ffde8e49a5994afa41d35c9fe105fb8332922859f1d2d2a7a73cbe02d4bf5616a1d266d866db2ffa812f8aef8e1e6627bf714cc4381a633758101f6b553f5dc9" },
                { "be", "4374f104bcdf2866311416f15be5d1044a37caeebab967cef6171714ad4967b8016b44a9325bfe0600aa04c9a978ff576c740c122b3f5ebd1e6462a45e97ca08" },
                { "bg", "48db7d388b6e46d939e7bf52935d2663acd5200985519979f3ad5aeb2369a4863048f992f5544e7e2bcc0542f0af3e15d205895790e9f5c2c57628a52d358b3f" },
                { "br", "4766790d33de70b3fa13a2dc491a7682c6adf5b38e2798026e85a4cdaaf7a9f89e759ae7d95993ba3c8ff8fe6da5d47f23809b32badcc9e9b8309d002e735821" },
                { "ca", "8f90dcaad58f3730a9278a10b984798b923fb7ede2501a934d0b0dc44dfb52aed03cb19aa9e9a8c1f0af4310b1549ec701fe4a32c15f11d15ccf3e72acf98a3e" },
                { "cak", "2a4549796ffc1c455b8194f33b03e31c782e9487d82c0964ca644529faea783c4ff04eef1b2fab6806450b0938bd3050fd129958beb956f5f811c0efda7f9476" },
                { "cs", "f8c478b396caa2773865d4da7e09d3fff5c49ddc21743818fe1350dc5ed54b81573d1d39386d4137e9b630e31354fbc4c811d1cf7de04052c4f4f3226d23d789" },
                { "cy", "877a83d44c99187c0d76f2fc6e3b8676a5ea7d16a3069e6e308569230bb0db19ccdd93c8dcb3ddcf2e3edb055c92bf610f6a2c363fffc63f4467134fc88d2a8e" },
                { "da", "ad36e73c7887091bf8cf16dfdf7367718ca98a2fc5a15ac2684b5b669322f05d7966d06e1ddfae4860e1d8876567f2ba368132597758022661882c0fe5b6bd19" },
                { "de", "b698b5b11a97eb9e41c72826ff674c22125d38b152b2f8ba5da42e61a551806027e58a621e2f3cee2d00b546286abb1a96de9895df0282eadd92ddecdfd14200" },
                { "dsb", "3d113f943942c52b90d2debe29fa834f3054cccfc66d440ac1ab73fab8d730c379ad5d25e2835d54f3c5b9f4c0d28fdadf898d7cec5be61f8a0615564a05a090" },
                { "el", "6362d8b7f495c9a34b7efc1072882a15e78d5cd04c519e605142680681da3c17fa4befbcae0b88d8496aa349fa4a74efff445f0a635d78943c73e84d92f42dc6" },
                { "en-CA", "88998345871ba45bb05aa73191714d77474e596714c6b9eb05a7a9eda77e3f6d468c301c08c0a4b1aef51b00ceef086eea7be967528eec87a80e50d845660e88" },
                { "en-GB", "d6632ae3d4afa108e5f120a8c77b67884511925e20ada88cad71760d1d6442fabf75352e17d02804d8e0bbd0e432354a697a00a2b886b3d4d55e6164d84721ff" },
                { "en-US", "c151688fdc47beceac2d4937bd18385190c539ddf8be5a0f3984b2be3e995bd78eeac2787ee9d5516d72e894c41ccf25e1b47a858131d87d9853207aaaa3e203" },
                { "es-AR", "1f282473a5694707cf8f498a66b9d53514b54e28089d844479101b62500657246032a96b789b8a0900d882a520ca41dc169b5b85e63fa96712f5b0295600784c" },
                { "es-ES", "67ee72c0b41b204284e0d546441e9dba26b092cee6ea0e5c0a73504f72bf4d5b19425a4cfcfd555f44e16f65c2080d4ad8eb1eb682d210b7ebb1ea6f27d523d8" },
                { "et", "7f0d67eff5e695c5a97d5c72eb8ee0cb7fdaebc82500773d24c07abce84dbd273d4cbfaba98885bab2466f9fcbab474bbbffcb4230d8e3bb5b65168fba566451" },
                { "eu", "aeb5b8ef81194115058423108baaa40f5004926f0565da01bcf8f9c64fe940a0f25bd5a0f780451e3f8079b5128801e2dda27eb36402a86f06ebae63c5ba07c6" },
                { "fi", "adc4584a9c1841cc11728061d80d66a66ca809b93694f63d814ee40ca57a31adc37331aeb32495ef6ff24590bd661a639f23fe124fbd24caafdcc1887aeeeba1" },
                { "fr", "024623e3d5db6979c2d3c23e28d8d84a8d89e2f84dd0060ef1dabd10ccb2b6dda00c0e1c3d1c7b6719072f353554a19c3f811ef7c83281ec8c31116d1898b1e9" },
                { "fy-NL", "4e11d635eadffa711ee83bbfb2026b8b70e23a77c519737e5024d8b4cf0e0d180298514ae1fa96fa428d2375207d20ac684857b58897471fac8e696356660cbc" },
                { "ga-IE", "01ad37f6e7ead7afb2439b73b7f916f53a474bec24fe1aba3709e7661be4588735a2dc75af5b55c30c094d92db739878c12b5dd3684ebc308125f655c2c37595" },
                { "gd", "68d7f1a7c09433e0233f370946115eb0702e999c9a2a71ab69df2bf24d5afc168e721e0f7b0dc9650fdde21437f762a95f9b7ebe02451b903b4a48acd0fb71fe" },
                { "gl", "3e54cbe8297deedd4bcc4f545257b3ab8ed2bcb8f828b38adebff4a5fc727e5b05dd1a3ec8c68d69217b226386ac7b2ef0e4ed108273bb80ebe7f42884153827" },
                { "he", "fe74237f4488d01103bb2ba2095b9e483ad6e0cd042b728b913ab21df5dfc6624b4b7626119f98feb130d2a938025fbea0440dece38fb25398572647f219f10b" },
                { "hr", "82fd890832b345a26b1f19e38d946387ae2109144b465ca7b5432f0390226e89c24dca2b0e35751cbf733a2a1a58dee3f64b06322cf7c5ce3b80bd211da1f914" },
                { "hsb", "fca49575fc61f0434845eb87f0e0dd28dcd8a4405622381a23d78ceec7404599f1fffa7566844d91e304d617b5eae17a4276676a8e5c664db9cb47f46aa11615" },
                { "hu", "416076a24bbe55cbadff4b3a58be9cff827be51980aae71781a0a96c788696ae90412078e564b59e23fec0a41f1169ddc8d5e9b6e735a4072924e8ea0b5b7456" },
                { "hy-AM", "094973007a98ef2f047bbed1bfd44c0d69244cef0f701c39ee719dcb885d5ec63c4513c5e61cb8217a4bcd0a0d7524dc2f3068dba20e5621f97db2629faa7d07" },
                { "id", "228d618c431a7dfaad2b2d45701ff6d70ec646be7663516d1f99fdc95b3c39a2e9a00f1b4df2422ec30db00d647a4dc7604de3f62b389267254e2adf6a6fc87e" },
                { "is", "d82ac6f0726570c3009a8bb7b56459922bf2f7ae5b9bd27a4ddf9a83c2cab173383d39567adcf1b416c256cb8f8fdee0e249d3396470fbe42cab5dfdf1bbbe79" },
                { "it", "7aca3d7ccc310b30145190a05a063b81be8d600079bf826a4c942c83d6c9a3eb1cf6ea3ad6a0a952a529b1ecf28c97f846d0ed399af1ba3abed76f4083d139c4" },
                { "ja", "08357d30ce72ea8e5beb137fd881f48ef39073979c30cf8a9c1014c8364939eb4fa01f9d26e2e8e42206b0f59426a5a11dd2d8cd21466b4bde00b4663659e5ac" },
                { "ka", "7b064b4343b0f893da5b90f27a232b34c8253e530cd99820abc67eb45da8188c495883f72ad6710c217571f1a839209d3b9354ad609b6a8593b159c8415a265d" },
                { "kab", "31cc9a7e20afceae926180a30e555f45d480400837381af06c39b9dac7a09cd9eeca6ceedb65b65057b890a03ad7deed8a74c4ec25ce395e016d5d021698556d" },
                { "kk", "460569726113baca22f0aa4d077feda974b29961830d69ef12968790e02d48c868d32bba743ecae7494a90a4654de9c5627940dde89468f68842ab4af90e8ea6" },
                { "ko", "14dcd49f8ec96c3c367525d2d7a81b278d9ac2b8182333ca7f33effbfb58b5b736f6c2476178d695d4166b9299107b7bb0ac8313bcf8e4a9c39ea07c23cfd2e3" },
                { "lt", "f347ddfd07524e382f08b26730393859d01d84cfdff8add0c8b8cf03218e2ff4d7a3c2937d7d2eae27dfea3d1e1361eb52b9975048e96e0bb63c2bbef5fca03d" },
                { "lv", "f5cdf590e45ff14f381629dd685483ecfc640ba65e6aaab6e578d6f48ec3806c4b6a0954192d9786398f123dd46d837850923200ba7005d1c9cd720cd58b12d0" },
                { "ms", "e6dd627bc0faec3e299f57b7f825688ae1c63a7525b54be5a2b1c0f4f618bed537157e97c2d28c0ce63f04a66bdbe73ad794b739446a4cfb72867148a4fc7868" },
                { "nb-NO", "0fdbbfb0a0b30057b818f70316136bfa9421da61a8b6d3c9f7c753267fabd516a0c26ab1d5199c95308ee70f76c88e7ec67f5570f18a7faf3f53e2d03d7ea459" },
                { "nl", "c2ce83632566beb4f1778728d1edc5ab34acfcaa37f4366b83fdf46846c3a4b27dba954528813c6afea6ef1b2939a887f7d5cd52e67766b024cb114faf0f7e73" },
                { "nn-NO", "e7a79c2d5414a4f67261a94cc1b31d6d89e706626e4ffac0540a520fd09fe6f22ffaddb8eba79eea9e768cf2aa02345c003d817ad0734d294292ab54deae36a6" },
                { "pa-IN", "9a7bb3d82d1a185a67a4ec69265cd8aec75a288613a98669aee4be98b10703e15eb1646d06f23ca43860a899e4f1b3aa0ebb899a5fe18c3ec5011ccbd3b9030e" },
                { "pl", "15d6cf0133987fe53b1d601bccc500ba874aca0dcc3161ea686caf9a850df1599a7f8b09291366bc42236c1b8a377ca882405d945f48644cfcef5282429080c8" },
                { "pt-BR", "ed80ca1d5fbc96cfec49998d2116bcb5efe9124c3191913ea1ad7e9f477d49d839b109b333a7923e1916fe47c51ef54d12dd0d0fec443c9a7e576e03fb10711c" },
                { "pt-PT", "fb6d8851cfee146485a41ce13cd80b132e81f95e75fc080a27226bc7b2340e5c4d08cdd82f140ae2f2c39b136492f4c1e4d49717e8e9df82e86ca2277645046c" },
                { "rm", "50e61d9422a5ba4db32197b1de4b824f83c320002c6a268ab61d28f4965a98980235916a91858c614571b18be10e8a5809372653b341df34aa77e760ebf0daaf" },
                { "ro", "610630f5f6ad7a7e38d8fca67f663dd70a8243c5ef46b59073f0817c87e35f41439e34f4a8cb952eadc41ece6616a8d979aa1df95f3d26e6bea49b79d353e3d0" },
                { "ru", "f85d7d00467f08006f6005dc39e81c7298ca1ee81fb88f0225196baecd2082a1670d07d2ffda45c777665238b28e9fde0b467bb226526fa27a52b6f42105377e" },
                { "sk", "4a79ee0a3391aca00e86a1a057e02aa26234c10f5c86e3d630904f1a907775fe36e8f0631f7b1d0908657fe239917fc4ea32ee4abfa4777bae062ae9ac8cbf48" },
                { "sl", "78b64ca13c9f860077558f02ed6ed33559f39a05e58219d9cda0f2fdfee358420d161deacaeba12165baad02a2452036ba98f9b245cc2ab037d9fb723910c32a" },
                { "sq", "e983289bbae3b75f5704c94b4f90fe7ffe46bba7e7d2aac81e87aa55d8d312a6e6c422bdb615903442fe71b3a6d9e45f0007b81be8e3cc166ba87fdac1aefa90" },
                { "sr", "1d5fbea149fddb8d6cf78d49163587f8f2a86ebd3ac0610340914a40d848694b42c95afc2b0cc5c15cbce7fee6f33f1fba3af50dce1cb1ba8bf9cebbf6760fea" },
                { "sv-SE", "61cd80c21d4f2354f37f927bedab86d68199449ddf75c7347049a97163301c6279f1c41886ad46c647991c5ca074e695a6e2e0731e0c5e35a8498a2772ff3216" },
                { "th", "2f3903498223bb478a07a42513773da1826c3309cc98f5a9d5ff176d98753068f17954e80491f5ea2eefee688cbc5a63912533fcc7212b39f6b79ff6ae144d9a" },
                { "tr", "46d72006a1096f308e183392fe3faca2fefc725d9910ee3406137d8c8c5edc09ec2b3911fa6581022954107294f863893d353a83eb2438089dfcf6028ec76177" },
                { "uk", "8eba8fbd9906ec5f01357111d0d0960fe7f728889d970dfdd5ed17b687f4ccb9567590f90275f572b8cef92812426c5cc81c829fa6b2d5a9892a9cd3988926d6" },
                { "uz", "f5a9523ab79c87ce2f6d8f3df7e1feaff5ff6c45a69251f1f6780ee58f1ddf54a1d176b4d74d255a37f6854710d1868533072a425a41182c3561f7e9e390ae07" },
                { "vi", "d32fd7f7f655d6d319e4a430fd3fd3bacdf5fe1f5af120953cdc510ea140fae657dfca3a64a0bc0ea546ae9cde0e8dc1ec8fea74b87fec739f22dc21a3ff9958" },
                { "zh-CN", "e6cdc7118a1015ba15048d086f1881a01aae9c39d17fe7b0036e27046ce19da1606ef83e4de0cf66b801ec04eaefe69338bfac3f1f72590866627b448b4cb821" },
                { "zh-TW", "433cfeb4a8718dd3fe5c09e813128620098402ef02668554a325b5b94ede01459e97a54e4262166d6aef461ed7a0bc09b0ed97fbf66873af3c9139de05f69521" }
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
            const string version = "91.4.1";
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
