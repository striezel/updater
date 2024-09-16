/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024  Dirk Stolle

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
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// currently known newest version
        /// </summary>
        private const string knownVersion = "128.2.1";


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
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 32-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.2.1esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "9aedea46fa334db9caa332de187ae6077d3d3fe9b8d39eebae28525da32673e93602c47d152ace03c3373eda21d93babb47e993502641f38f32812fdd597ab4b" },
                { "ar", "f65519e1f54dca4135617f6f403409e251fc06a7e23a67c7e1070cbb6235d8156749f8a3ecc524785a5b642ea115b4d86adca874716e192c9fb9ae592b338909" },
                { "ast", "9f3c460c0c4f9d16d1f62f0fde9d203759dd41479a9a1b5c15688cc813d8f6f89c794c4880c1474959e75ba9e06756442694983b4bd26201cd5c830670f1c78c" },
                { "be", "40920f2d2f6bd8553464c591793cc0f83ef72133ac59ea2418dd21ec46ee431ed00e81461f4867c08b9f7f2e583da3a5f9024f35e6b19c7df797035202b9d0db" },
                { "bg", "aa8a0fba3cb20b5322db72305c859332c8005b5baa5733c012c5061b5674f7f1c88af8362fef4fac2bc7779a5853493ab01d8dd65b92bc7a3a17426da3c0ab62" },
                { "br", "c2eea9a33dc0afb6bbb018d925d49c5f0158dad8ca2ff4744b0f7ff0f68b6e390478ce73966761c02a8e64d19d1da6f8d37f8835e13a5c87752ddcce9bdd8124" },
                { "ca", "6051d19e564cbdc1f61a8354d56aff247ce4aa75d89402c39bfbede7cf4342f0aecb35f5e34bd90036f29f4df4261f50a9e6ac0c177d04b93961cdb229e53c44" },
                { "cak", "3d5e8228b9cc3a8b2d1dae77a4bd71ef9f78c67be57050805b35cd1a2790e1585f676bccda9c0e898434570eda6031b3a6ca6124536148574a83c1e861cafa39" },
                { "cs", "80fc7bfc343f12338170cddf120d0d2d7e3b8ea44b1528bd4f41717eddb4ced5dc3539817efde5976e651d04a1f32977937882491ea38ca62ac2ea26725f7b1b" },
                { "cy", "b7172975114f0a3a52db89915de92fc21bacd95aa3179127a73ebbc68c145241c67b61620f56409e24be588f0174eba2cd09229bec54841ddc036d7e2f744560" },
                { "da", "9365a7779a14993cb8d9523fb7e6a01af679561da2ffaa4e5c858fa2477644df3d149d3d2e74a74da197b2bb295df3c4a1fe638d2b9929ce8e75a7f7349c680a" },
                { "de", "eb941d98e302a84eb8549f11891d7ed14181d2c017b721c2a061781221e7ba7f264bd09fed3895c802f4e53cd5343c152e43983e9bbe553d0560195b9d3af34c" },
                { "dsb", "8d4e71f6e5bc82e854976a36407be1d8fa0ada28fcffd0abae78b674933bcc19809be8c63762870ae386b9f4d087c75ac1eb8f17301bef142c1ef8e7a848b0b5" },
                { "el", "ab9788d89947c0a471dc9a1a23f9cd097fa18de54da625f40ace86b8e788032467220bf5e9014a8c8884ea7572ebda52c1e39a4a4ad28c904712d8f5cdab073d" },
                { "en-CA", "452716b7da977f00bd2d2858ef8d365349928feb6988f7e0b3f83168df6d5cde4fc4b627d977d2e7e1d2edd202bd16887bd1af9ede836b132738e61bda0a2147" },
                { "en-GB", "25ae74ed8bddef005ac3a99c8df9e73399a292a14d257ce9832fb03d1d6845b5a614e4457bfc0b3dfe4d4c6a950f2f9273b0d5afbdd1d8fe311c82d6260fbb50" },
                { "en-US", "b1f8f56859e9572575a5a50996675191f147d0cd4c8ed68d7567a17ceebd5fd6739fb07e954b7bb49a759db41c6523bf59c600dbe05bf125dd9b6a875f4d5a42" },
                { "es-AR", "0a235b5d9215b7d18775661a1096c1c546741517b0c5a530eb7328a9a2a9bdd25d8f1e1b65d78ce94610abef070642d0c59ab7f2eb722090e60d91fdc649c2d8" },
                { "es-ES", "0abcfc7a983695e2b7ad856550f6e5779b18e2a9e886f6d574294f7d4d74025f1cd44435760f4fc1e11a744ca475a0bcb9ca4bf70d5cb992840265046763b2f3" },
                { "es-MX", "f608fb8f2c296552487f29e677d7a7e5dec88d97f612c28f169db8698dcd2d2e687e86ef9856e2ffc3bffb2cf4362e13259d77b43c9bdb05004eee87cb81add8" },
                { "et", "b727a2efca1f13cb4c45d1b0f6a46ac4cb89334e0ee42cd9b9fd51e777396d6b93cf2102a18d7d78acfa3583717c3813c55c93cfe1a3d6778e7ce88c28477f45" },
                { "eu", "8cf55776775d7839468aed8437d3d4c9e3e75db71d8a0da113eacf5f6c8f64653b2b45ab56838c97327cad852c48bd6f695418a35a7de44ae399c455ac657384" },
                { "fi", "46ade10097396f6c00391f63d7dee44a58597d4be4502e03ac87c19675cf9f7a1d5a66dc675a89ecfad5933570befe8e5ed0d3189186b18adebf1108ecd5720b" },
                { "fr", "6d445915c31911449eb4a4aff7188295592a7fdda2ad72dff765d12a78a886fab8ae5baf2ab9190b772735eb9ecdf7207ba1b58d3f177002d152b4617cfb5476" },
                { "fy-NL", "1062d26d00ef2883de968ebd68610c7a08660f684c95f2ff0d2efef00c479ff77fd2e9dadce014a9219b06ce76d64e529b96baa2db114be6988e7e8918ec3044" },
                { "ga-IE", "1644652695b8cab91da558a9114f264063ba3a5a1e543f9f06e1e955c28ebd2d126faff9d649ea6af365301ac059ac9275c2cb5ce88fee8f0dcc7a6c6609047e" },
                { "gd", "92be9a88c1cc9d41c8862eb3b5d1f214bbd88f1eed1c6753df72ec51ce012d551dadc0de29f73a8f639ff6f3d206516c9bb5c9b5a7676d79295116d6ccc818b7" },
                { "gl", "f274ae3a6815730a1a903677c4a2f059a4cd996096736369c21ddb931d10b6f02c9251312795530c3a42e312411975a5f9c33cb12ab321621c57527669b00b52" },
                { "he", "70b8f2d1036df638a8450960f7fc6de62a8c1c3da92aef8406b6ef532285b07160be7e2a457416b03ccfac7bc4a44972bb079777c60968fd212a85e1034335dd" },
                { "hr", "baaddc9a5f681fdb70c7a5c0cea52bcc93660582082eb06f7aabda005a6d34cadc46c58ad26ec8760f54b32d70300c05ec1b0cbb0bf567e61ec47d26c55025a9" },
                { "hsb", "764bfcb5685633f80aed43f62359ca6560924cbcb74ae7595248d115a37d636e6c896cde760fcaa32325d9011fe056301172a7afc32213933adf4b9c2f2a6383" },
                { "hu", "1ed8fca844a87093eee719dbbb2568069d6a86cd1572de15fc85c9b0f810153aa4528cbfd27daef6cf88324e89bb429766a4b996edadb31bee0320ab19e92254" },
                { "hy-AM", "699433dfa2a8fd26e380445516ddbe1e30fa40b6e595061e2682d624f7da9be0fd00713475b06d5a295385a80f8431e3b4a379dfa6631874570201d509ab2047" },
                { "id", "bcd322a72ee5971435b634d1587bf89bc8b0c4af917ce06c81044efa6cfbb5af0478e7f6e847678f29f720f15e279efd89006c21baae1c917504d7f061473156" },
                { "is", "19dfa1526085467670991c660938ae7499e6dcbb0621da0d6128e16ff7b8aa3904ccd487de9ffdd1e6a6095e6e8559cea7d0d55099568b348fe921d97c3051ea" },
                { "it", "ec047c7bfa03d2ae40535019108d2f5fefca9c980308c4e735f3cf357a48e95321a47148b3846c0f0f2736a529331670791afcfa1f568116040cfcbfddf8b2d2" },
                { "ja", "9ed98a30a87a81af78e1666d761c76f7626bda4d45f5592b28e271b70103ee01f0978a10d13e70dab1f8a6b99d9f66fa620c739e5e2de4eac6389395b82103b9" },
                { "ka", "cb1d5c8fb703ced58844c02a2112cef9209c80f1197ebfe0717a5a6431bf16a521d5085701cbc74fff80889c8fbe496b32ea012e300fce4145eedf7940936263" },
                { "kab", "02aa7a81de12910c2f0ad63d8a57a0f3e561f6176e5ca0fa7856122ae32a7ca3990279ed33e3a5e09b41dcc3e0ae3219b1c29ab672f33ada96e7ac820e2d289f" },
                { "kk", "5642f1fe7f02f58c484184942c3f70740368071f3ad51beaec743239f0ffa0be3cc4933162745ff6cd03d6fb597a40d1696960bdabe4a255f80b6fbaa6009fca" },
                { "ko", "b9fdc095f61c82e05f34e880545b77db9789ed054b0b35a47b3fe5f1bbbee46f295aedf333c84f7e685c294616fddd3b96104fcc4e788cbe3d36bfad6fc9fc4e" },
                { "lt", "afd1e0fab3d50e862f69c6cac5706b20b855a8bb9e0ff64f8f2911188789cace9683703eb77eeb04d804a7085862cc648af4588cbd864d78938e7e0d28efc657" },
                { "lv", "95db13e90a7ef7213e507ff6508be8c5c1d0d93689795b88b5b90f03283023ab234ca98c6b9cff71890760bfd75fcac99dfc8cffc9b13a80f9feb16d1a00da79" },
                { "ms", "180f9aa14c18181061a78bba4ab6eaabf7dbe8cecbdabb1053906b2b95948d4f540fcafcd43b286dacd6d4d8016839c11b9f7d3279d71a4e17579ea6633851c9" },
                { "nb-NO", "aaba426b261a3bfc1cf605793d852416d1921ba2de77e079fd343acc71a7f2e7b350e858c0aa895fb0f3810d717efef2870456a2ca485b20e46e5ba0f4690393" },
                { "nl", "996894d48a5e05aa03725e780ac7f1a600c9bd4f5da23ac4a544a3e4ae0c0a7610664cf7a37a6bcbb84f1a9ae78957b6a3a143f15502434377ced9f0b1395cf3" },
                { "nn-NO", "6cf72229bb7689c857d6230d5ed93b5bb35b73a26505675b18412f17b1516af4f90d1c002bc794673678c419d12278f6c1e536e8b4b07e8e73baa570069bd790" },
                { "pa-IN", "0fa255d96f1702f2733cbcb706c11a341b20c58ef3200fca2a302b6c725670628ddc27e5327f8393e74a00cb9632d4bffaf911b09578efec8816866b4f9ae7d3" },
                { "pl", "a202e855eca4c37b3ffd71b475ca99a1ff25d947faab3c683a7ffd7a4ca9fd1e6d6c8ffb127fcffb9895fc6ec1cdddfc7dea3c9626d7009b63efdc8337b85247" },
                { "pt-BR", "356ba5677e21b8551791112d656a89e51c9020da188819ed275ce77f6e050162bd055c97668e9c366657667dac0d7728ee86a66185279384568d36cce2b7a50d" },
                { "pt-PT", "828236436b32b60482797b0321be1895b7111e9a08ae46095ac03b9e0e8fbf23832d2627a5c50e688414c8aa4f4ca95359af3b8fc567e65da31da9a0dec186cd" },
                { "rm", "2857abe623eb95e0c4fd29ea5cc37909d3d88122263aa90e5a16e1f9677f136ca22d394cd8b646398147d6c41203834c041ce8e5a4ba243cb1405226051a8188" },
                { "ro", "60c3a44dd80e6dd7f9aa20ea27cf4b8cb5b57aa7167cac3d78a78d0fd5916390be9a252f2d269327a2511dcb7ac0adbf631cff83dc3e4a62519df8b83b603122" },
                { "ru", "a655fe56b8aca3f9a4b53cf82bc5d792753f8a5a3b7fe8285b26c6ee34c5e1dad584bf54dba4d613eeae823a2823fb7c5253909b8976f98cac9e4a3c839ec377" },
                { "sk", "d80761213ff22dab8865c8b7bdd799bcf0698f4eb0c361ccd653645e78a431b76207ad4d39e3897891450992c5487728c09378b15a4a4857f6688ed706871f47" },
                { "sl", "cf9448426a56425ef12aec5d2c83014c8ffddd428404d510ee174aba95fdbebedcae0fcd1dfe655ea02c253865abbff4467e0c2e13e250e2c39f5806a8ffc73d" },
                { "sq", "1624f8a1ea015227587da49fd48af2ba9f2e138bd2182c485f31acc4fd510ef78f8931ebcefbd28d60e3a623b8f21a1ebc3f22a8083930ab23c3de882a5b9f92" },
                { "sr", "a8e12e6f914f93c13767e6341ee897e5dd5e35d1ccc62b7a6afe16f8f1914a86182a7a9c699d68f67a9287900aca2be6be1800c3e443974482af833a258ca2fb" },
                { "sv-SE", "d43d0bc704ff36a9358242f116deef7e41c8eaf4278523f63c7ed353faac8b223749907b79c9bb2f90b4cd1bcc8edc962f2731d69f508d511132eb1f6b9563d3" },
                { "th", "ab9571ef86b92dabc4549a89ca4a717052381689f0e938617df72c516448308179215f0faa05f660876153f0675d65f44464c6f8c1c120f7db53fd9c71ae74d4" },
                { "tr", "f91fcdee79b660a7716f7c3d351579b9fe10f4680941491e1c427e3b90950acffc3a51b3425f1fa9ba1b8c805e6aa9afab9affd0b9783bd08c72cc339d209f99" },
                { "uk", "7c1d034555d11bc4a2ddf40352bf2648d6f498e9be4b2508e1bfb59e9925b2a9eb2bbef77de7b801ed856c5b9ae49a5adebc9cf7ce6c540657252a35c2801a50" },
                { "uz", "9b32af9a8827deb51c162d75f0c96f3f4930e1d95fda83d86e391ce0c02a7264c65590360c91008410d1191cd676a9a3504010fe188cf346fcef3086227d9853" },
                { "vi", "1959e4412e0fe46678839f4e79ad57d459d985b230673fffb0df4b9e9ff98602a90ca4e4252be41b566f496e2f0a187cc5398a8fbabdf6a2eaf0ea319b579c06" },
                { "zh-CN", "c7d52d141db5e83ae6e58a164396319626677d946100bb8945132dbc28399452a05d14791a0fff826f45f0daf620bf8c08cca8a20379f1b7e72821d6b963c3df" },
                { "zh-TW", "3d9791c38f1ff49a3fb9caab05efeaf39d4ee988350975cfaf0925d16c7d7807d4bf2a3b118c9334d3435aa94cd97333f521bf15ea2dc31ef5d407ec893c6314" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.2.1esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "6d7a6f3defed9f46d8cb90901613a088398f904da15487fa99d126fd85fa04d9b3f28554714eafecc94198ba7e61e1cf829c3878ed870e6c37af92f30ca99f94" },
                { "ar", "d39ea7943092cf80debe5250eecb8c614e8728c3c2dd8470c485b16842d8c0db2d0cab9713264361133333f41368ab3f4c9bd7a800b829a4f8474639e6f95a16" },
                { "ast", "e690e1761d9aeed402186a1d92571459882e48747cf992845ab149bf2d4a85744532153615f7ef8ac6b000a2fa9eb00364f9f4fe0d3a3f1b5b97520e706c949a" },
                { "be", "77516c610f05e62d5da521b376ac896c7c876be264c95e233e093b8ab752aacfff27d1a6ae8de0210186d3b6364cdeba39245f378206a62ec978c7555845ca2b" },
                { "bg", "3576f7c279a76982e9c283a54e7aaa875f9c79b8a0df4e8fbba9ae3bf7aa10c18e4b7b5593e672077b67c9dc1b5401648d5797c4c3c6ea8bace57ee37ad2ac0c" },
                { "br", "bd7923edbc519570884d3a019e3c67c608cf9bd2842343ff22013f538cd5300970272266c9bc4896ee21bf59f39a2243438a0056fcaa7d00a18819cc71ac76d6" },
                { "ca", "0afebdfbff3512d3fd3ae2028f3ea04ba4d601752a7e02b9e1cffe5685c71b04829e016141a753698380fe17641f85df362ff818ec9c85e4b3fb28b0f07afb29" },
                { "cak", "d7377ab3731a4462081e4af27ed6932cf72549972bbcc7fb831afac8a17cd46422b8c1ea85bfbdbf5aef9b158fa833e77283bac6aaa4c3172c71e71054296743" },
                { "cs", "a7218cc9f00ad18cd3263b52e1eaacd695e5ca525bc599ebdd7e1bdd42fb6feadde67aeab677019529264d1cecfb4278f55148c8804b1387e78ada441c0812a2" },
                { "cy", "f6cc20a8e27b7502cb1c9707090719723bd9219f89b13effb4e4374e721b01f4234a495de6a0693b1d4ee6ea9969c692ee5e80f8739c53091d9fd2922ad0bbb7" },
                { "da", "6989b71a827a32de8dc541e1524e60ae15306c8ed236aead1ecbd6676d01068f44567f54c0aa833e4614630f3559cc48288c72cdcbaa3b225f1d266c13d00d9f" },
                { "de", "dd5c6bf1e0e96d3a8c253bb37db3052985b3f884d1abc43d78bb20f955a3aa0dfb6b708616ae848a69ff37ae32c7a069b5b1ceb1edbaf49336c677af5cc7d621" },
                { "dsb", "ab8a54ea9eb6f037a9311ffce4c9aa3c5a836375ed3b58d19af2638626ddd311baa242f0b7d051a116c6a663d61e64d6bc741e9a1d956e177d88e52d319602b2" },
                { "el", "3878c0e58935e77a89a95247ea6bedf4df249d1a0c0ebb80709dcdf1b00fb4573ea02eb2a0a8bbda069468c489afff00c8973e86f8eb0986e18d38153d89f2dc" },
                { "en-CA", "e419d528e9d88d456889d5f83258c6838be511e04f441050c95a1f2ac771dfb7537ebad04ae2c2e982fd32ddcc0f3cf9944849a182dacad6981735a8de0f4584" },
                { "en-GB", "794ac124533614ef521afbaf9f22b3c1b718f6a2406604158d5ebd9ab54db6fc8607fcc4f09f2c5c8fdaededd94300d3dd9c61a231389c2a36fbd7cc4f0d5bae" },
                { "en-US", "ef75855188dddfe698dc6fbb5bd06f61025a77e7df5d9a713d15b3a99d998df5a26ed7663577f8d0d4a6efaacaa69718469c13646cc3dd87c777f530676c2ddd" },
                { "es-AR", "4e182b3bb5d02d1cfe0fe0cb1cf970846b3e7d28553bf94a299627777d5062958278e41343a5acf27d50c2289382f1e4af27389215a4d11401d1cf25ff462157" },
                { "es-ES", "26309860c19ebbf8faf74429337b022cca605b1052d9fd0f9544a1977403b9c78af92ca11b8fc0a534bbff8034dab883d655d10526fa24a2c264d55cf01d026b" },
                { "es-MX", "07a64f43b38ce2535f9f6e9299b7223c0714787bb864bb4fcf48b56de6346728bf1bd4470c19c96d1e7bb7379ef511bc26facecff4abc81b3f13e36d3619c5a9" },
                { "et", "383032d7ba3232d5ffa067bd7f8571c6bf98a0efdd6c0b4a42db88ea52de767e9436ad7eb32ef6d47d5f2f71395f375a03bddea9b02f626d543c50526ca2ee3c" },
                { "eu", "36b2eb2c12b40d5d41b5a75701548d7a3fdcf7813b4f3ee3aad783e5e1cdfb30adf9bdd73e19c544e65651d47c8060ef34c9c127be2a46b55cf69541a6a76d3f" },
                { "fi", "d825c79ec57b878171e0b724a1a092ee5ebbeb74fd44ad66f09b5d1728e11e68ebf26588da9de6a7252e909bcc3f281da2e56381a092c444c71800ee79e3afc0" },
                { "fr", "0e55f5d647f89478d0fafcbb2ffed2c9eac124101a16e5f962fc6af0405851925bd643af02b9b45c88ec9b5c7c1082d3aa410fa79b31a69017f9a22c12c740c1" },
                { "fy-NL", "60ebac6200f4b3175a33ab0dc947b77e5782c56085b20829ba2cdd5b1080d7ba77bbcd8e3f08c7393f9cd528b08de3d6f26f62ae3c23cb39f2e74a576ee69fe3" },
                { "ga-IE", "684f55a3b44440f3e8b66369120adde3c7ad458727bcd8dcbcfe740707ead4ef9be43fb4b32203382455ca8c646b3def823f0bc5add840c377e1e90a1534cba9" },
                { "gd", "c0c01281e1f4cea4e741042b5e38aa8dddfd52688a479db7b5b4860f27da4b0e5ee045a7b30588348c0da649760003e4633ef58ac1832d857c014a66d57a1507" },
                { "gl", "fc87f44b87a688a4173eb67171a72f106a530fa1815e4f6de4309be8fab4300aaccb25c3882f2bc1f6ccb55d1f6847720c9a1077def64b074df36ae993798640" },
                { "he", "d234a2180799ed3e671a552066d3c0ed41740047f7154ec0cebee89ade293a5fbf2da641f286216d1580ec6015aa0ca2c293dec1e219f812fbca55bff02081b9" },
                { "hr", "ed6a4e3a3f3a8031fade73d88f352d65b286bb089ef575de0a2394fb74c771c2b9bc40938f4b6cc5b92926091cdd762d9d002f8c0fb021a66bb023b7e9aded24" },
                { "hsb", "22f5b8ea16bf46a118cae90c7c427522c24ce5c79d207afca428c9c11d3fdb58b4f7e03daff6fbf298297fbb4024ef2e587b99d10292bc511cd3ad0380309034" },
                { "hu", "556ac72bc4e65b5d313e83a008290414f932587b03e764fc3312f71d76325e6cedb6fd1cc9ec46fd5ddc0509f6c6b452ca51f6bcc6dae899dcac770eed82d4d6" },
                { "hy-AM", "b27c97f81f93083899bfa374954821db43e81966cb042df9f3e3e65907e48255615f8cc416787d494528bed38b55180acd9bb1e61e54fd998423d74388b63e02" },
                { "id", "86929973ed4fedc4ad6461bbcfe0ba8694c9b79971733b373e4a07cfb4e6608a445c1f228b2c05628de7604d004e234e968dd61f844ae55d368326bfc4263d86" },
                { "is", "3648d495372a60e79206154de742bada29cadeb5a88a83890820ec98177b034c43cade1bc2e1b743cb6c90e2cf884415d4c9e1fbd3095885f861ddbadbc8f511" },
                { "it", "833c400c3e4cf5c44294e3cf57c0717b4e35d81ba60d6f18334dcefd2b417f2bf8b319f9d39194d431b1ba01ccbe043cacec841f96328720c671bdaf63afd269" },
                { "ja", "45a065cc843fcc5615d60f0c10cdeb6b5f0027a87568569273510fefc187b2df65deaaa07c93d12910aee1725176c8e25a6aa3ad5d2ea799b956ea3d1d5dc919" },
                { "ka", "303597f6a3024586b86837298e32360f0d7c2b3e2b34eff117bec966321d3d5b71d6199eac0c41f2798e71e530cc1d29be5e3cffab47ab59358aa75761daca13" },
                { "kab", "0ba93f716b1224c659184ed786db13a7621efbad37a636f78350c127b84f9334c8c3e5f69172d0c64dcb55dda6a4cb3f0ee6df99a56385788e725ed2eb71a1cb" },
                { "kk", "13727cfd35d1e463a2bd1f73e25967555fcc015be95cdb5a2e46ac2cc4170a6468c386018bcba51969a210a4da91f5981384eb7090f1b3c1b5940a329251fcf1" },
                { "ko", "1df939af2d7e2f91f78f91e37078e38721ba145f9fe68785b6fe515199407c0fcbb58a57d3d37f7303be2b739c424ec48b90915a28c9b380cb37de4602778002" },
                { "lt", "fdd72c345eb59c097778a62eb96a640b241082755faedac8ca55e9ce181d1720d7cb4cd025d1e9d09dbe22cb9f7217851d9a49b6c0dbeeb9ecb8af85fb27412b" },
                { "lv", "76c411bef2b4518686286e0e4c9f519846ce0d823cc3b6f5704b57bb6f88cbda4c86720f548b9151714e7cc345b1ff906858ced0f6824b4ac6a8938c58144511" },
                { "ms", "bf13c2d5b9287a0d4ed014aa03cc498a50afbe407f56c1077e10b64821fc637fb49d8821c2fe8d6255d5ce183ea41c54c0d732bb278b80e617e4e1d191429d39" },
                { "nb-NO", "4409e3d881ea8ceda2992ce9dc14ff2964c95fd492f58ecc1005bd39ba28463221ef53deed5a5aff8ccddae7e1ba78d0452bb5933d7fc383ac0cc914d040dd3a" },
                { "nl", "948fec2d88783cd57a776f284276541623fdd6cac917c8e4212907b9418c6a573fdf5dd04a85d33d9c69aa580ece0be4946073fa9f91d8dc2a001013ff324774" },
                { "nn-NO", "bf9429d4c203293dba41286c09d5999792c732817f9b4c5c00c713a5195ad49c6068661f2f5cd4a08786d3477163be982138bdbf544b0e042d2acd283b8d9114" },
                { "pa-IN", "bf3b2cfc50076c3a9dac1af7e6b6509c9d56b8402534e54731626e1ee7c9c936743b15e3fe204f18fb7704974ef41eb25624bd33fc36c9db52871fbe6dc6a703" },
                { "pl", "dba1d2affc379fab3e9b95d2663c2bbff869f30aacf82847d9afa3594a8229a5d134a330c552fab927ccb0d5685096b0e6a5641a9567f9b7d7fddfb53f90b90b" },
                { "pt-BR", "37ab7dd24774bd415cc29cdb432938cf3a8c1b77e4445af6a22c4d39da3e810db0d6067f4431b55a4d808a97ad4cc42903fb507d2409d19663aae9ca77a3f31f" },
                { "pt-PT", "df498db3d9bcfa740964de0a429ac5e80bf9cb18ece1413afa65b5bfda854c06d8ac27cca6c4de5946ae59b7752213e6ef48a2e80575b6d963e9af1dac530373" },
                { "rm", "f35603ca45d958b002d72fc91d7f6979ac9eb25494a50ce33612fcaf73e2b392ff69dce07277dc0e9e9346ca43c326d2e9dcd322057f3016165868134ac73d80" },
                { "ro", "7287e7158696d9c2089fffb5aeb13f3daee71fc1bba8f4b9a07a3c095e3195389b59429a6dc2de6270d0937180baefae26f226f7edbfc953cf61d32a6320100e" },
                { "ru", "b1271ae3ee2e5e612e47994acca887b44c5ca85dc9c13f47cc4eab8db95920de534580627b108093bc0053285feaba39aa400946e1cfe39e1d8a80d2395a2c2a" },
                { "sk", "c252c9bada040abc5fe521eb2b7e93d1ad135003cbae3fc9079445dcf2f81021daba4b36dd229731476b1c2fd7ebd7a685996fd807776d4340f7eb211a3229d7" },
                { "sl", "f099aefbf0d27153f9050029628c2a12ad0ee5025e7e3d6fe3c6c05e8f9367a5793294014c8d552477cd7c91c09a84672eef917a7d4b880361260fb1db4a956a" },
                { "sq", "b4b39f9c60a7a27a2c2f21ccec8cbcf4cb57da6081b5d848d29e6d0c996d346c0c2522526e35b999f44f1dcbf7b680a543f90b5e862c8485b2072dd968bc5889" },
                { "sr", "28777fe6cc8de1e1a1c0cbb7d6ae8dc7a53eb08adbba554a52b17e377c1f1df23e4b96830e1554aaffd5d6e6cd4664eb12720519e6a5fdc95639d353a5649f7f" },
                { "sv-SE", "0759891b67d5cfc62e215812de529f1083695f3ddce82698e19d848cdba29836300a5270ff21e62b0a4be3dba0e4a4951769729742916d6296dcc68ed9e20973" },
                { "th", "c34db2bba6a07d3b4a81447610c27e5e5af05a674a84f4faef9b347355ba040f0be93326f27ed85419d6207bf830b7e1af9590519df06fbd53434de44ac88161" },
                { "tr", "4f98dac829319e735f0e98b5cecb41a548e557236bf4b6943a2928d6d725edb1db51b4a58a44b4d9aa4b161cce53be3b65a182e73c6a2b210ea29d8fc3b12934" },
                { "uk", "4473f090c96f87bb0947da4306910a99a82dd9beb12bd4920b93355fa84b28dd5c04134d744887fe0a342d757e1c137fcdc0b232c96675394ac08cebf6f6aa3d" },
                { "uz", "68d76ebf0493bc5a966f941d7cfb8616fad1bcd2ef08e48be59df961bb7048724de58b4e46edffb5f1401aa6b078ad1a95050d1c642fabc5de3694c310d4c52b" },
                { "vi", "e6f804cc6d41633212b46f5699d51b8e3a9723ef8de362005074a273315a2301edc2fca7fa3e830d44971e93b78273c3e41f70a8c318b635ab5aabe9773965fc" },
                { "zh-CN", "5803a9358d3d631e9d11cfc8708518170f0d61f55ba6dd715482d6100835685b83c620635260d60b78d97d81f541ac2a3a307fbda1f4205409039606322a03ad" },
                { "zh-TW", "0f74153be90deb52877ffc6b5938aaed2fad96fa06a4cc212e297729d99b4e0b2a751ad1089d190bac0d79f23aaf22a5a0abc68aaf7068edc63c623361fb631e" }
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
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                knownVersion,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + knownVersion + "esr/win32/" + languageCode + "/Thunderbird%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + knownVersion + "esr/win64/" + languageCode + "/Thunderbird%20Setup%20" + knownVersion + "esr.exe",
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
            string url = "https://download.mozilla.org/?product=thunderbird-esr-latest&os=win&lang=" + languageCode;
            var handler = new HttpClientHandler()
            {
                AllowAutoRedirect = false
            };
            var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            try
            {
                var task = client.SendAsync(new HttpRequestMessage(HttpMethod.Head, url));
                task.Wait();
                var response = task.Result;
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers.Location?.ToString();
                response = null;
                task = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;
                Triple current = new(currentVersion);
                Triple known = new(knownVersion);
                if (known > current)
                {
                    return knownVersion;
                }

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
             * https://ftp.mozilla.org/pub/thunderbird/releases/128.1.0esr/SHA512SUMS
             * Common lines look like
             * "3881bf28...e2ab  win32/en-GB/Thunderbird Setup 128.1.0esr.exe"
             * for the 32-bit installer, and like
             * "20fd118b...f4a2  win64/en-GB/Thunderbird Setup 128.1.0esr.exe"
             * for the 64-bit installer.
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "esr/SHA512SUMS";
            string sha512SumsContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                sha512SumsContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of Thunderbird: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return new string[2] {
                matchChecksum32Bit.Value[..128],
                matchChecksum64Bit.Value[..128]
            };
        }


        /// <summary>
        /// Indicates whether the method searchForNewer() is implemented.
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
        /// Determines whether a separate process must be run before the update.
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
        /// checksum for the 32-bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64-bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
