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
using System.Linq;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Firefox Developer Edition (i.e. aurora channel)
    /// </summary>
    public class FirefoxAurora : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxAurora class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxAurora).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox Aurora
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "131.0b1";

        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxAurora(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var validCodes = validLanguageCodes();
            if (!validCodes.Contains(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = knownChecksums32Bit()[langCode];
            checksum64Bit = knownChecksums64Bit()[langCode];
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/131.0b1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "869bb670e8c8a685e282586a68490eb0642c30a62a481b93e65c5824f8249da73a375f23c40bd7c26474493b40ddec7c5c33e126375e0e1922ca4e427dfa8e89" },
                { "af", "5992e70925d5bad4a58541703407257fd3c2f78522acf12833bd47ef2335de1fb09a87c40e1ef314049ab0b5bd57e72675976742cbacd6d39a97aedddee8a61f" },
                { "an", "8de2c5171bf7389c78abd7a6cc1896f7bd562e90c7433653039db0b4ce3db97b4987c9955633a64a4206d65a86023d76fb4e26869a46bcdac404518ea5b0bf16" },
                { "ar", "d837bcf2d9d6e63a6432d21042bf1f0880426a775de37a923cc2d6a7439c3c2dd9e106b5156a062908e18a49960aabc337939e7bfcd98a97494d7fd29874e99b" },
                { "ast", "bbf61cdb3722670263c765751ec07659b3a4b12d0dd1c3fe008f385c31ae3f08a5e69ad68a7ec7b61b45fd9a9e525d7a53f1046e6941fce9a95d9b66e9a00b1b" },
                { "az", "bd1c6a9d1cac9455e6f2896f42592b9d023c257bdaa5feb1bbf8b492718a94b6a1b6bae02e026a18c761e460f77b9f7ad09c240af8797597deed02d36d758b1b" },
                { "be", "86698002ebdd17484e32b1d9a9f8b51c77145f8fe0907e603bd1ea527fe22bddfd6ac04d0d1c7135918b11f443fbe9100ce64433ce01833d89ddd2fcd6bb0aef" },
                { "bg", "fc9b63b6063f899eeb03407354c8101b91b05c75edf5b6d773185da6a49b1d08a691c9b8258f70a1eb3ec0219b5a21383ca47b80bb25730ff58c961cffb910ed" },
                { "bn", "b4433b6247e9cd412a4999ad5af2a774bdac6e16fc53e89ac547ce2840cc7a8d3da2a491a8074ff9c01fce32aac6c6deb249c67416cddd78e1b4bfa391ecfc5a" },
                { "br", "5b8189841f3f98a5c9ad6b0f8fe8211bb30ba5b9baca8e07de57745a24d531b997653b26a8369744d8852deaec6cb781a750cf999bde8bbc2b5e89198c2d5eef" },
                { "bs", "036451dea64a1b60f87ab6100b285df17f54b3384605ac85f22653b92bdbce653bb711cf97398b13cface8b88b67842600118ecde96cc7c46c1b6799e7015877" },
                { "ca", "96388e334b7fb5f68c15d283e3be85b5fc9cccfccc8545a3daccb3ab5b2a041541f5d2e2d5e56ce6330acdc95e3e07a4d7ae8f73ca1482c48cef08401107b791" },
                { "cak", "6b874cf9001865f947f4b75a19fb70a23ab4d422f6e1d31b8e5686c263f8288b8aece899d217aa90ed6e2bb8e58c511b6833ab9b0e6eb07448b211b0cb60373a" },
                { "cs", "6795cfdb7baa101852e299d77ab213e4c3e9122f766b4cf5d1d709898747ec1899af8a551009f606798430aba8efef57feedd85331652ea9a4ed38b41c775331" },
                { "cy", "00dff550cbb0e37f4dc536e60f73d5c55e3407d50050ea44398b1755615d16fb9b4ef4cc196dae92cd6d5cac33a69a1da16fc1b895aeb3d8611323ba8382bf37" },
                { "da", "d7a08573ff98b3acc21e21c126f9ae0eac6ab4f9d2f4924d9c988159245a0a9bcde09c8d4973a388a5b2c9f1f7b17893af654e0aa85489c1a9c72f21c2f1c1af" },
                { "de", "f99d923d468f06da04bb21c73db4a3c1de26f1699d573b95739903db0b0114951b74fd7be2b358d084797032e42f350c7b5aca65806aa4e306406375cd467086" },
                { "dsb", "25331f92e9c5bfc15690b56bee758ebf1c0b5c88b1b1cf705d56a91a6c3ea16e3ba106370b2837b0a8f53eb93d911e57c28b59687b56d514b9e0bc829ad05035" },
                { "el", "0b1b5b387ecdb17fee56bf7acbdf9020a462f6059c06ec8a1994002be4e29059c90b1ff842977b3d4cf9639600c9efa99092093b41f4114e48254bc82abdb179" },
                { "en-CA", "2a27c3972ef6ba8fc38b81221620c060015ada8ef8b752e7fcb7d780d1b8a0cf431b9117b591f8ecc053e723d7224b0780cf9bb2ba42eef8acf7e59ae15c649e" },
                { "en-GB", "e318c4bc4bebd13fc8188b273863addd43eb1ffaf8de704cfc36375a4277c3ac83a05a19fbe3909bcbeda8718cb3ffe73833222babab9dcd0fde184e574de468" },
                { "en-US", "faa4075d0b9486008600345d76c3356ca7407958e7f037c62fc1bfe7e63ad25adadf861fc49eceaedc2b1a6147aacbf068d28b30accf25b5ab2cb80ee5e511d3" },
                { "eo", "9c4bc955efa1e03cda52561d987b8dae212c6d27aea4e6368579dc6c03b4144e820fe26520ad625695307c3b6f0adb84953a3423bbe739cdbdf813cb8d9a3ab6" },
                { "es-AR", "a5210725c27e7c8c4ef242bca3b898128a5ab09b0e9c05a7734ac26e3dc6d067f7900e7ab7b3c66877e971ca04f15e9efe7b8729253360e15f739b2a8e711a5a" },
                { "es-CL", "e285cf2c2f619ddb47f6a6e076b552f9e17c147dd40c26fd8f9ab68cc23faae7dc1195fba3d67875cb35c49fbfb597a64286a52498fd4e4f66fbb21291bf80f7" },
                { "es-ES", "b39eb007f200870404897a4a8006f90796955dcaa936c5b60ef938aed1a83dfa9afe4b6e9c63938944cd63b6f66cdb6abc9d8751a59730ac0b34766c49782edc" },
                { "es-MX", "87b095b776a6bb7a0cc5c2b6b252faafd36ab8e31b64e6e58b97528a6ac3d81bcf551f2962d7594f061701444e7a6dea803fc48903833c1b8b3bb03ada39616e" },
                { "et", "05af55c8e21dd98d37c96f21aad5a8633c4e05208becf38df5ecaccd01e50b8d6060662567f931d2a0bcaee51a0c0e97dd6db0ae59225bc48b622c2b9e27d210" },
                { "eu", "fa31c4745433c60bc6ebd597c8661a631a9354120b5ef4d999c7630fc99cfb6eefe7dd8ba81e55f137a3832ced3ca16a03109f6872e7cb014710dd05e8377067" },
                { "fa", "175b643e32f8092fcfd0959640d8a50573d1a8a8a50688ca4f16786be8b8fd2938f1dd20d94d9ac527035523041a599dc7bff8f5694c762a648fdf7f9b5ccd22" },
                { "ff", "dcd3e703173b3445b908450a26869aefb7b0fdd03fcd396fedfe101d2b7c4cc075cbfdf810ff612ef880467b5007606a23e0b6c1cae36f52e661c288b48fda90" },
                { "fi", "c3ae329b8335d2292c726899e9d68ba44cd039b0da0d8d995dce6af788c9d2c853208b936ed29eb692aa3fd9ccf5bd9c92ca105b0d28dd12090cd62be547350b" },
                { "fr", "6dd81dccf17a9107349de4cf00349f5cfdf55576c6fa5c039fd22187d1aa61a5972eac724122590c0cb6187562bd3dcc2150a6dcbb69d1b548fa206d61bfafa2" },
                { "fur", "5e5320734e4d5585e03cd063bb5d43b2af516ef659439307b2aa1f7c9a16291f89469282a947f287136795bd6ab748ca525c9c62e02feca471bf22a7571c3c3a" },
                { "fy-NL", "e1370116007f529da4874eae0e58dbb5d66ec6ae221a5a1e1a7bd65755efbf626a0d45242b5e396a7471fbccc7eb072ec0f262b91594b78f964243779cf041c4" },
                { "ga-IE", "1965b84f065941e7a1eb1ecee4c5d6d96d972b7fccc0f592547019041ff55249f501feba19b2d76b46faee14ad4e72785e859344f39cb6405c62cd321155b00e" },
                { "gd", "f4ab98dd47c0cb5a47a515c25c3ba51271c31bc33e783e6891f9c564ae6569ed082370deff70d3ac8a99c1869fd4d7e263af360a6fabcf95ec61bf93ca2ed292" },
                { "gl", "ac2bedcbdf153eaaaa9a38db4178ca71beba53a6a7972f7eedcfb13abd024f668e6b4fee7ed2f51cb1d3275cdc92311b9b3df8fc9d4a31777c46df371946fd4a" },
                { "gn", "e0aa9683be4fd2debe7aee7b1cdc72bc6328055ca5022f42a1b952ed861b844c6e9c26f344c8daa602c558fda8a420d8f816d4e9ffb9bf1c3ae1dc28474478cc" },
                { "gu-IN", "cba1bc798c097d98670d4dc709f9e659b4df8a7ba16aee772fb1bb52b94a565d5bb3866686da1232d21372fc0eea8b5e37678956ece5e5ff6ff94ebeb3abbc2e" },
                { "he", "c4ed60bdbc1375e8b1c5b4cb4017e99ba3e44da95c449a3567392739ee2ac7ded132593bc4fea7ff9ebc0e975894100beade01e1c64ede8158aed3aa3fb6c8e7" },
                { "hi-IN", "489e0a5e9124e12d0db224700e67e71dacef6d4cadb530fdd597230815256b16b524b10e5802f4265612c1cf226e58f1ad65306768d70a8e6bb1b3e698859d36" },
                { "hr", "01bea18fdfa40f101d483599e35e655ad2e468f99b5e2048a4d9a88e31a429f2bcf35f27adb651d4ea06d0f499707f84243c598715f7388296e7e7a9b45e5ea4" },
                { "hsb", "b63dbd8a54dcde16442c5b1a4bd62a66448f97bb9f4dbc5549cf55536fccb628b4d1a5c3d8260f57fdf742cd16b949af6da2724dff5353d79d5c671d0cab3034" },
                { "hu", "6b2923d08cab88700466bce0e8a2d4f7b643f20838073590caf5843cbf105244f9edcaee5ace44b40296880672bf8166ba1c061649cce565a54f1577a7495352" },
                { "hy-AM", "3587d38e874d82fbb0b69e9f8eb4bdf1ee25d0507c8e6454178a77bc9ddf8206c26ca50d6274469835bae8aaf88f873a2b4bc2231e7025130124694b2be5972a" },
                { "ia", "11ae0cff32e0a1357888ddfa22eaad9419b8f47d6b840c78e80eb7732faec7663cbd8a3bf971d13c600ace6bb8199ced713a900a43504c405dff6addc528d60b" },
                { "id", "9d196163e6b6822f0d457d2f0e13d2bbe9cf6523b29692c1dc3216a8454746c57f6ea76a854c99fdb1cefe7eb406321e78a23fd4686e7ba4480f0a19acc9b409" },
                { "is", "0597c5f105c30dd01fe8c3521b4f9d6408340defca27f59811fe0a10f944766fbcb1f5fe0e7895187eb529bf1580dc47643dba82ba9ae20d31b9365bf2178c5a" },
                { "it", "3ad693ca3e9f2a2b60c005c2a75abc50d2f81daf2623b44f1f69219bc9e431c257925a9ab19d90f11ab19853e3a0163d228eae86524444802e194bc1cca3ba7c" },
                { "ja", "2ee45c3c5188763747437df22529eee620e0a5229016c8a0e9e92c49787121e9ae3d84f0212967a3e558a52ffe4043f5abc213375a4b4696aa0c3fc429cac473" },
                { "ka", "3b49298d568c0d5b47744f3d32497961d0eea981ec05a239312038fb76ec13205e82ff8c05915f6c61ecd675c77d2fb4fbc836458b860e8b00e9af85261c8e27" },
                { "kab", "428597a9797e23683247ab224cb16a45f6de9b88efa3449a1962b4d75bb13bddacde8f80e7ff77a07bbeafc109b4f92d8a7ef469f99fd86aaa2b8e39c96c5118" },
                { "kk", "08335930d051dca85fa1bb98445b0575ef1225bd4f56214f363c06af81aa9df3a4068899c3b7f3d60b9a857c014f6c6acab3a767b42943d534c22f5149bb65d3" },
                { "km", "8694a089cba2df707bd57bae39f926bd5d145a336d163545354a48f14fc02cc0e18907cb6c555e465f01c63e7e37e91c1dc6fbe9a4c178934dc011ce90bef14e" },
                { "kn", "1c29045bffcb482380a784f22de984389e22af6ee55eb94ffa0fd9166c210fcef1616bc3275d7837b08a9c42e429d98faf819892b42416bbd41431ed93e95ba9" },
                { "ko", "db7e7afa87cfbcb232759794be0fdac360c90c46bd183c0824698adee6661149084c83f7ab60f0bef361af0d93f98f93604bfb7a7900ca125108e0269f81fc0d" },
                { "lij", "965eef0a3a61c07577022304219b50c86a52c201763505b9bc997bf34d36662f71a5d6bce57f6d9b835d20172b227a8bb508adce86f5e1a5f4961b9052516086" },
                { "lt", "019ee0bac002c92747e5271d6eba3124c55a3f35dd14d008528549bf48840aef87f7dcfdc5894b992dfa5ec85bd40f984a9403ac76151d6a7fe37ce4342f147f" },
                { "lv", "ab3a070ffd2b521481292cb3a69ede0d9ac7cec8513e0061d33d687869ada2288349260c062a9d2871df62643a629471270c9c831bc15dfe9cb4a68e9e958616" },
                { "mk", "2a497b603d46d2cd7463b3b831973d6652735db8c8d33e4a83b1bef98dc93404d11ebd835afbd61261e1e1f9d01bbd4d1ac8e0550bd58b615a64507c94c8caf6" },
                { "mr", "2cba7d479ef5f941af21c21b50e990621a9a453d023d36f21660575fdc842e26d6d76ced3e7e273aef5d04849f116889028aa504788f46bfd3fd7bb9ebd19f7e" },
                { "ms", "caec264b69e8dce158ca6a7407192c657be41faa82074d553302cd54593d5caf3db9ee0e8a72cbc7f3bd1ffa79dcd9d98c408c8293b8417d83fea8e814cd70c9" },
                { "my", "a3478194500c67a2292fb2274fe7d3ca0a502ba0c996f045f2b1bc553db61d07000d4c5b8eede64ca16679ada14a9972add80148045e00eb2f226048bb01b672" },
                { "nb-NO", "b94dcc84557b814735f7f7a3aaaa5164fd71463607e8c84fa920590d09f3451b0a2a07ecafd885fac0fdaced55d5457bb857eaf539910a27327a5f1d5cf118d0" },
                { "ne-NP", "d584dc8a0d9ae3df58e7414e873e51b44d565752e595d178c40a852432c5f9b3510e3f070c3e2e05793ee74b0493881b58b6b6e2d5b08d65077f61dcdbeebe3a" },
                { "nl", "bbfe131051a56ac0ec3d10f7bc0a02c6382b031609d922c44c98b41251a9c1c48a95fcf9d2aeb3442dd2f5ebbc893359c1ee1ddaa3131f86bd5732be1d7ca910" },
                { "nn-NO", "9d3ed5b8883aa53ffb60b2a447264cfeed69e2f667aefe006db22d78785ddb5eda2fe3ef0a714301671e46057e4cea0f6218f99c2406861cfacf1e53b62bd275" },
                { "oc", "31a68be0ffd4fde912f7117f8f0efc079a928d66b98641f0aaf074ebc3939a82bd859c094d4dbe7c595098582e53eccd1a53167f9c85c5fb39a973585e0f8705" },
                { "pa-IN", "ee914d5df0266ef0d44df81ed7c010106df71d896857fe3a4145a870ef44153f8cbbe2b9b910c8f0cf2c871059946d254577fba254b32d456658d04fd24bf580" },
                { "pl", "018a4f70f2c25c7a551f6b34154cfc571a15f0b0dd371c34a1977b402389f64b22d783624a87b6c3a9c24b0423cb06dd72f459fb435eccab00436f0f1c674e8c" },
                { "pt-BR", "861fac7ec04ddc411da7dbc7bf573c690615c695b6656dac47e0c40b4a318bcbf48a99c58020e37f71e1f303059622e4701f002b81818d0f9d7c417b3ff0c16b" },
                { "pt-PT", "8e31788f91cf61b36437decb45cbd4ebc59aca37927a99aa6e33fabd6bce25c5a1189d90f8a0e5f3af110cc50041b4cdc8a0c6c2b48ab727d4c0f3a9308ba6f8" },
                { "rm", "7459ced1297a75e7f96827123d644452c299cb33eb0635118428136d7ae8ed966f42a33d438d51a851c08779dc7d27979537b7da0fe83290016859adf8fa4497" },
                { "ro", "5be9af3542e0b74ce554917065ddb5d4d670d055a2914c58aa929583ad331c30e9d524a1be2449890148ed26d3bd7c7d7fe106f046c1dd4a265fc83acddee2d1" },
                { "ru", "bcbbbfd0c8bfee08add6a654409e3b626538a3eba09212e1a2bb2a769a80d28b7fd12212e4e50433b11ccdb16d47d9961302794bb0bd1aef270628374e26d579" },
                { "sat", "2031ec9653dcab75273a69075092aed6d1d49ff9b756efda4da843a6c2e1004411bf48c06a687189ebd78cffd1c8418c3acffb642d59d45ae90f519bd595654b" },
                { "sc", "467e09dace706607c99c826d0668158cce63678f01db4b623974ed2183e66d8c1960b01e84bd859a569df3ea899ea4daeb407c8f597cdbeaedcf530aee023b11" },
                { "sco", "1adb21266c3f3524125915b417ada030f6c666463c75b54dc64a24b462a938d985ae2e4bf84eeeb2647c9240d6e693c1e20fab462bdad1889131e1add045c383" },
                { "si", "2b37f6f2a3638ea28de04e305d9aac76cbc9ad71d97cf11245fe4429c03a3a2063f11b478c9eef0ff6860ad7f0f9e30a92bd3de556d02921eb250f0a13572975" },
                { "sk", "33b9d517434c12b88237d983193d4c6703313246abe153149d6620c6910b178da18ea273092ff1fd7c305383e7eb1c7c96fef1d7dadaa17e192311f58903ff83" },
                { "skr", "152ec36926d583747fcd7a11b8de856cab860fdd6eb2d3c38475dde185715b8d5ac92946b652e1a1e9d73793d48f067eba1d60cf0e4291dc3068f74103b7da1a" },
                { "sl", "fea435175e2f3c476b31cd649812aca0838ab9c1af659fd597a7b3ac0e077ab371ae68af8507484f4727926cd8df53e82672d5cefaced566682eba9e18359a21" },
                { "son", "2bd5da333237222d9c2c774fc90645e19788738319bd9cad281d323ae20f9bfe7f47a7045a98a22d44788c993792b84b9946f714402213c2ee11240ea01cd818" },
                { "sq", "f67bf7836471511d45e16396c9f4f306d118f35f497d37d526ce35c0ba3ecb56364943f6dc19efb12bf025181225b1b7b898e48d85ea82d3469453f3fdaf7fdb" },
                { "sr", "5437f39a9a909176a13ca6a2f9b311a372e20a6a5a1352539b28f86a6c3b8f0a69726983a544cc3fc2986f6f26014fc20d2d6ccc8436109132695d7c149fafbd" },
                { "sv-SE", "dce663328ac6421b1af41590878477fa6ef25ac40c86dfcc4017908d9e9dd335bbe22c7bc1f17d08d471d9b09cf9191d4790cd3a85fd82592aa3395d0546da6d" },
                { "szl", "f9cdeccee4e02615c7ea391a2e024b1dc43161e3bea3e9c3ad57e5b02b400d91bc98cf8ed813db75ff23b169a8d11a8ce3e4cd099096a2e8de8e45a105631a83" },
                { "ta", "432f0eff95a0af5a75a6fb6908da92875ac2c53212973d73b5872610e8bcccb1f685d21365f029efef5429edd8a424b2c761fb564ec1c5131b1944bb002b222a" },
                { "te", "90daa7d6d3e08eb6b4953bc517f4590b4b6834f25e42b9167c97bcb62ce50738abbcf4df11c31cc0a67f1a496eb4ebd6f34160d2d7fea2e332301bbca97d9f60" },
                { "tg", "c2d354a22767b32b57acd4a6fea079824914996541b8853d072702d91a22da6a206401c9fea62f441e01d2086fcb5ee3a9fe9b0b0c21be013e8ed554783ffc10" },
                { "th", "3f738fc6178fce52211b6226807efd686131c8997e656bc7c8dde7883e1d16359cb2c5f127945aa0f28f581959d533a560c551246085257ea83434908b38e5ce" },
                { "tl", "87ed10c2b3b50f5e26548aae94200ba00ab6e203cb17af7f2cfd4f0482c04ed10a081ea48c7aaf3ed438c68f2ebb31a7495b195f520cb16641051b667f9ec485" },
                { "tr", "4a62c46895242e9056a3636434806c74358cc1f5776ec8d518f434214c6b901277add58ee7b72d5966dde46748c19c35c648e07229888cb0af4a079362783287" },
                { "trs", "2a1acdcf420456a43732cd0a4cd8cfa98d6f1047009965dd914a73ef5ce2110c9965ba784ab6e5bb72b4805eac12ab43c0fa1221c116c2f88af221c89e40e7ff" },
                { "uk", "05eeade7201100a7d17a6713868ddb9840691254b12fa002b4e99192b2f1201de5f3f454d2c3428119d411e36055ebb1b1ca58ce37474096a77733aafc523546" },
                { "ur", "e1f7e51fdf0c2a0b5606b08459e3176bf34d75c652f8b01efe2efe90564c9656bbf754a8ed4caff5e82cca9c782e4e6f064c42ee04924e887c6944e331308386" },
                { "uz", "6bd9115c7775fd9b8cf9cc8667717d764db5b94d19d1e4c9b9f0bd6349d5589f587f0d68b840b38659af1e5995995481d80eab2ef2070c40a8276d194d55cab6" },
                { "vi", "ef0910a773365c2f4d3c18e1dfe02a20c45dca9137f37a0e9906a8da216ff39bc9cf536692b10e9ae92f7f748058803a5598a8b6ca07bdca2fa3d538c1907685" },
                { "xh", "0747ef787e17e15f04b58d08043ee3d755460dd79efdb18d4a5dbebe8fa0f229b4f6a9205eed56da6c712c9503a60e54ac8542b145c0bbcae66122c4866976df" },
                { "zh-CN", "acfca53cc877c77c02819818ec58331226a54a330a139f93e3e640d30a0205577a6ee048ddb13523bfad261eb86e60ffdcb2a9cde04c5a707ee3a95453f67ae6" },
                { "zh-TW", "670b81b7ae34d5cc4b4b709d36834600dde39483445376d60a7538f5c57736d38e7c5ef7841ce0335e9f62d39b6d28c00b82770c89adfa9a959440563f80ff75" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/131.0b1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "ddbf236322474cf3c158b2c1316d92d8dc32dac30ad300df3a59ee8b32499703ab7c2d6e1ad84a87baed1440cd4ed46334918f721fa7bd8dce2e92a50baadf27" },
                { "af", "5869f4f76eb7a118a955b3cebd32e0efa42f2e0b0aa17ebda381e57ddc79ff3c7c1be4154d06690f16675aac951a1595fd18f0ebf187dd333ec88541218bc357" },
                { "an", "7b53af284f04dc12ba1ad85859b915fc9131318be5552539d948072b2dd23a2b91a5d766f12b8223e14079ff26b0692f04fe15a292244fb3c1757397fe24bdfe" },
                { "ar", "c7990bcdb37f416500ac7c159a821f37400a78c99505a9e80dfc99cf0943cd99596d5471e8ad37d2dc25d73b52c3ac3e66f4a4908da8496ae692cfb95ad031c2" },
                { "ast", "72bb1cfdc4ea3da3eeeb9c782b4da11298c47f6e98bbb984e9407777a3a210b966e8305598c5bd40e0a0472edc7a23e0baace2eec16355fc6bb96cdf7e42ede9" },
                { "az", "5f611da4de9f649bb18377a144dd2e1cbce69b1f4c97982808f70fe1a5842398783b59c85452c114556f56d8cbffc0ca4399096754b9418f25336108cddc148b" },
                { "be", "013fd675f3ae4df2cddc47a74d8a6ca259c7ecc327e0569b595a9c5f0abc6e6a298c9a77ca76eaa7d56d00498aa58e4bf89ff0712551e241dafd1a9eb4024764" },
                { "bg", "901b2bfeeb91cb32ad00ebf4c0249d95cc93f9d13ab89eff3e99208f129436234bf939d1e61ddfc8fe9e504738fd0596f21ce143842cac97d8f68afb926c65ee" },
                { "bn", "500eb1cc0cba8bf036b69ba0c942e7d0825683e4aad760e729ee30bbe21bda3094da6ca1a00b3074ee6ea03604631900e719c5c2d4531ae3043405b22e253783" },
                { "br", "36ba6c5c97febf0daad0ce35f1c38bc724e378c4445d48fc2d253d944e5c5e84ac2c2651253f394754c311386686ac73da991eb65657d7c43c768bca0d5c9990" },
                { "bs", "e8a3bc647993ff73322540686024116cb87cb517c9152adf697609cb09c422d0b5c211ae6ccc757dbbd4155df5d54d3dc69a6955f56f1b4071a5463deba2ec2f" },
                { "ca", "1a6311994ef3845b808d67f0ee649e3eef49184071fd18f20313b40c35151b33d5c2b73ebfe95437706bd2882b72c1243bc5a946b919f89fb37115121ec3bd7a" },
                { "cak", "fde7b287c9999145e996cd6940e0e3b4c2f48dc1d3c9b67904037d9b09cffd395bd18319a9786a604ace351078dd95be17940d8e6f3e001c565a7722368ac3be" },
                { "cs", "e518fe96957db0e1d78887b8872d962093da08204d170c46bb9b8b19f13c6c2e0e16765d39fae3ba9fea221fd94ae2eee18b7e023113b59a64fab5e3dc68b394" },
                { "cy", "e5a7ba6602f202569925a24a6620cb1234d5f4f34a4663061437c3ca9233c4dec4ff18b04550d1330af5a4d2d6d95589ca51bd88820b0570a644b1acad48810e" },
                { "da", "c625167eb7274aa587be20af6dd477bffd777d7f817e45cf9f4a59e682f394349e0a7c865f35e9e089e2dcd6a8efafdf7b0a4a3b875aaee522255e2a2b1fa012" },
                { "de", "6520af6bd7ac8236e5baf35f751401f0fa318b0c9bc9438e9b6be1bd61b849a40f78d0fd51dedd07a898cd7d26a5e9ccd32b303d4878d9c8298a7bcb6c5494dc" },
                { "dsb", "50ab0d27c7e342a8a74792cca6ad583eb48a660cfb86d7a5f0732e6a02def71884d9232ea416c16f26f5431f3ecf2016335e93e5128ba32b2ce7a66a4499ee4f" },
                { "el", "1083e7c809cb0bdcb089c1bb7bbfc1ac70fd3f590e8df0858dc84051ba2a3308406ee83e99407ed52d61b1103c44be69db13784299b62563eae08ffc05540956" },
                { "en-CA", "bcf4b7a7e88e9beafd5576c6f5c62326f6ff9f9a4a6f9d10ba9c87eff3f019cc80b6bf64d2f65a6f1e76785913ca124dfe0dc848c9dab9fcf121338d115ad4f4" },
                { "en-GB", "92de9c977998ca728d07f8e3b9600459dd0840aaa70409dfde7e163e5ed3b9de7b7c8c75abc51f99ddea817f18d8b3bde7efdd5dfbe907bdb3b5e18c1268debf" },
                { "en-US", "b97aa6de34f271b010a3db8bab2d29b1fcbb810166716f625762494d34496d6b14de0c6f6633983c538ccb0d166183e439464388a5fc90fb079f8ca297d08443" },
                { "eo", "7333f831899e7c75687d0e02f0b2a941591fc4258db310f3bac363b334094dda3c70983fb8a33a16f924a8f5b5fb03454856358ab9ad213b5c6216b2389ad240" },
                { "es-AR", "4083714c690e2cb541958acd715741c52288ea044540867d3001f8bb7029b203db7ab31cfe6d0fdfe29e69eff5dafadd403d302d60537093cab052d873fe6536" },
                { "es-CL", "6a3387ad64d240cd043e343b53742d4c875080dd4f674d16ef8b2c2f2c44a404f776bb5458c84690562736cbd3a03d4e92a793709c982316fb01c9679751d9a2" },
                { "es-ES", "0cfd99fc1c8aefe1937d9574cac205afe5b6e96d67d196ad09afebb18d03aee20ad3c29beb3605bd64b9916ec6a3e0a6870cef3b7841a332c8b48fe76848e41f" },
                { "es-MX", "1b76aad1b94e434c6080bc923f6f2368cec2ab1d88788f5bc8ea48010379ccf003870c48e994fd57bf1bd082fb175c557accb7f62bee37c60557de9894d7b713" },
                { "et", "da6e1cf9b46c6f330f2cb93cfa3a89a5142251bc22039f7aacf206cd1ad86386b6323423c5465c6ae4ec7432f031fbdf200f2a17d382165801f71406a414baf6" },
                { "eu", "676d1e841fdbe4cc9dc328fadd6964e875fd4b94c998a8fcbedfe79bf17e4b523e5a68c3211cbe40412f0623e8a403c24e97e64b95b25a151c8a380543c19ffd" },
                { "fa", "28d3ef05831c765d6760acec54523c6ee4211992d1ac31bda9385e1f9fd0e18acd6496c8c84e016e054eaa17c4c82719e5f188ccbdd8404b6eb19d7ae8e02ede" },
                { "ff", "9a0fad275f5e08280becdec36066584e4222dce55bb674c6f2154f59ce16a1942c68f6c73acf75bda1a3d3c321d34a86bece8e7e55a1ebd5a47ce49ea8e54b01" },
                { "fi", "e431679d6c3c85d4c17d02b06269b39cb4b4c2c3210499de9c5b24715ae0c542bbd60f781bc082807d5f277b62eda6c624aaa1aa3292242e28cc46d95eb2c33c" },
                { "fr", "d0a916350e86e216bd99af96fa7827dc2cd9d14285f01b0bbe91b249a8b2b33408256721336a11bec2da2161f25d892a70b49826bd8149312f1c8465c4b6257b" },
                { "fur", "98152ce03864caff45cc53a4f9d989ba9db3c4bbf3ffe23fbe752b96f7edc1adc4ef07a65d910a09461e78a41b8e013fc06a0eef9ce756b58c1cd2a0d881f92c" },
                { "fy-NL", "7457f9c8c799dd72f26ea2e955f24d8ef00e6678c433f0ebf56b75874d939307aca82baa7cef511e012f1f860d9b1af7baf9dc4066d6873416380a72796a76aa" },
                { "ga-IE", "e709c89f8c3cda051c574426f2a7b2f0770f8b53933a2c5ad4d5cd81e3955378114047b9ff563f8214ff198098970e20be1f322bad7218d1dacb378d3d936372" },
                { "gd", "978f14726a113b1217db30944b802409dd14f71d534debdc1c8cb430076d27e93c23a9d516b7f031342d3af344f7a6aabf9354ef3a21b6c5a526a7c5a9a4ac52" },
                { "gl", "af67e5c3b056ad1e508de971aa0a17c617c5467c6d053ad86cbfdf0669cd2412e04d085e0e62afecc5e147a0001f5cfac90afd26a0b26ccebdf739a9070ca06d" },
                { "gn", "23a34ef03b7d25c7ba8a1adb446d03aff6c8d7165c407a3856605a4c3e49c5b42243b3c0bdca4474318578ea41efdbc5ac818bb62894790391b19a1c4e2230af" },
                { "gu-IN", "d43d0bc986586d9ecb310078f6e6408a0fdd8ab7124ee5b57fd6f821890e5c19e30832de486b13456c9af56bdbf8509dc6e941d51aa0d40487d7b579de6aa986" },
                { "he", "a65d992fe7004a7d3d1d7729a766a5b5966fd9cb530de6a7d4dbc3f7810ec024a85005a1786dc26e4b7a39d940c4449cab9b800f988a881fcd8678389bd1fe95" },
                { "hi-IN", "0c5a1b39970a98607ef9e294aeac4781868ea7dcedf64b6612567119d83df117074179ac669c86f754807b6f11a6c14f61018f98a84482bb888a9aca742d9ea4" },
                { "hr", "5d1981da606674af2a2ac4065779eb9df47070484d62643341afa15b0b770428ca8b0341ed9899741aaae969151c3ab7ca2aca24c867aa046ed23b570b9c0f6f" },
                { "hsb", "f0e52b4bad5424dccbecfcd6d7c42eefb627aa2999b296528006acfe6006ed4e518bcb85118eef8b0aed976c8f5282144f8086d79559cee871015328e7b699b0" },
                { "hu", "de842572d05cfc69b6bee9bce3b9f10d497c7fdcd7f6ccd89aff3436901aa2da31d2af5055a4a2fc0ac9b9d3b74aabacd861103c982947e496d275bd68e736e6" },
                { "hy-AM", "8eb974062d02f88afac664bbf77f278730daf5901559feee5c09b7d017739964d60c9b0231d06bdaafb2eb64e870423eca24a2787db2fd3d2f0438ba279ead24" },
                { "ia", "4b1b6ebe505fa03007e15d7310ebc2c185a5fb49e03ca61644e91488193f2fa87dbaeaf1408073c934fb56fad40245f4945b6a7f7a20b015d505260a5c7b01f6" },
                { "id", "8a8e0ba6894ca5a719de47fedb2b12f18e5e4ec6c8bdd8c0061b0d9e6e471724fc59b41d82d81856b35680ef25c582a0024fb0c541a85202e648fb55de9c0dce" },
                { "is", "dcd1b733d5c8bbf43664408a9be1c6d7f8d4c0f424aa58d4e088ae7d9620d171d0645ffc725536b5173de1422a80a010bf34dae25bf73c11d7cb904cd15f851b" },
                { "it", "4c1da3af046324df64ed4b39dd4e00eafaa7db89e4c8bd8d67c3ce13899d1c40952d995e70fc904d2c0e47aadd5de5621b3e1fb3ffbd93756c439b8cde5e16a8" },
                { "ja", "9ef7e34e08122ad95fc0de51d20d1dfbb96b7c5b14331ef094a567e0e8abb281ec0a1ae71c0054a7ba1c6536daf1a5660216134e9d409a5bd50c0b7c3eb942d7" },
                { "ka", "b68c0426d0ad293067a343f97c0d5a7d5865f3116e42654f07f8eefb390cc8b0ea19741f66f007cbc3f50f2d42027df97969811327357243c339da81948687fc" },
                { "kab", "1b53e5404cdfb4a6fd1df39ab5585d53eecc81c7c08771e65b0469493f815c09f0297c1e1dfda34adf363397071191a85047cf6991b02e1c9e7baa102b16ee43" },
                { "kk", "d011b69f4bc0e6f4a488d1ea1dde6bee0e69326521dd539ec44d83bf73f538adba11e2d0a884f5f0587e1aed78e910e18082e0eac9a121622d2af6f8b7dc1f16" },
                { "km", "e53dad6b672192ed5d79bcd0e72c2e37020e75382470a5b6e65b9889ddfbedfb35c5ed6a3a8cefb986f9f8c0bba44994414389cb58e8bc1e3e4f36420cc02026" },
                { "kn", "df1707cb235eb3565bb2f4d8b50afcf77874a0c05053c97bd70180237887db044d5ea4055d94c197095dd7a18d6fe8b784808f9d30c663f63a5f5f0e34a79614" },
                { "ko", "2a493118cdd4b6fd66d7e080d835a45dfda2262aececae36bfcb4bd0ac4e5919c5d7b22db9e41ac290c0fcc88b4da0d4cc0c2addb8e69abe5e23dcf587a4ea22" },
                { "lij", "18ce19fd349bde8b373b262978807597f9b5691f81f2c923b948895770868b152a9b70632103a97f0a9d91de49eec4f23dcd497fdec26bce53cc2c8fe4999f68" },
                { "lt", "18f269aa922a037decfda1b7f392425f46e0886f5c6d5185bc689f2a08d2fe522a074cc9e8309c1325132977eb059144f685c53ad290b665110395f0a20386a0" },
                { "lv", "9d376771268d15a50a146b44d2aecc3626b45847ebbff99985883b2f03be51a57f67b2261d68a298cca04a3b8abe57e592c9b80bd714237e7bf9cbda58ac108b" },
                { "mk", "d6775e4d2a263036a706b0a2ed02acbf00e24623625c9c48f04d4eb0a9f62f26515e692a0753e6f47c10b265e214d812f03d6b2cd4a736d4c18f992174f96837" },
                { "mr", "abfb1af17eeb110e25c1e2d0e3c2c955ec0d475ac655f9ad141a2cc8ba8462070d235daef038a74f257a5bb7262096273f01bf6b7637c5a8da2552af5ca1cfb1" },
                { "ms", "61131f9934cad1614cca4616e25580d6917ea0428256512428e20b8ade6397e08cec35c33154bd11c43bef4bc17c8c32359cbaa58eb901b7df4da334e30845ba" },
                { "my", "c49bd998e00964d17a8fd1dd32b86d182411c3269fbc6275d544438f063b3435ba85cc2853dbbc709c4989458f2e0b168e30b05a11b06f1266a3c9c7370284df" },
                { "nb-NO", "607054b8d815603e0ee7f8fbb12cf70387d9c372e7932d7241f4a8ab170e1fe48512652a0e35e53922223069bdb86395968c6f6f8e3c90342981caedb8c6d52d" },
                { "ne-NP", "f989e06b738a5c2d99887f91f907ed0cf30a9611c30a69b3483321e60be90cd1bbd8b3d875dfc9cac102a5232d781613b3623483d4875b5481e8c622b7219902" },
                { "nl", "80d28fbf80638db505e24c6fab459550098ec054cb5fedb3eaa255a9db8e49e112e5c7d75d9075e6a5acff2655da28a8c1bb1c07c59700f29451ef5fd7bf68cf" },
                { "nn-NO", "746ac18740544feb9bd7d330d1627194564bf792460eca26cc5e11393392a8e680d9ef5ab90eb9a73d36c8214cc95c650dc9b8bd86490e62542dec9e23f81f0c" },
                { "oc", "b0431aae9b3b2badefb2abea969fc63981c275ad1dc29b3da49f458a307d56492bfda96e379c390565fedf4e7600419f22c1119c59aa75efbbd336e6c657ce4a" },
                { "pa-IN", "1163c83ff719c74f91deea5d6484bf7b9ff423b795a19d842a3e6861fd9b0b4741987c4e80e1f7cfb068db8a02cae0bc2df07e64134bd50b27304f38856afc33" },
                { "pl", "f66994dca260c9fcdbaa2356799731f4e8bee6d28b6f97337ba13ab8babe7eb8548fb183938f7a4dcd222e4719c98e0173898f8d09d18454801321ee425132aa" },
                { "pt-BR", "0b2b17987cab5e3423868aa011f5c9c0eea77c76da3a2734038d6965141f7d338707e3965a5217243dbbcc0bb40ab19fb5eebe174374f750f5186154653d1622" },
                { "pt-PT", "21bd49760d740732be3b95265d509dcf6b36c272624f733f3cd0cee699f11f45edc2531abf4714f89020b7f7ad24eeca7d044053b84c1cbd7e4427be58e27fcd" },
                { "rm", "1ac54ef12c16ff1149c58964763cc68d7b4eabf4c1997919467c893214660ce3ef4424edc3548abf4cedcdaab0ee3776187b3b53bb5a5d29a6ec94bec79baae7" },
                { "ro", "eeececa980f4271b5f1828cf64341d6faf9c2c4fbd1f5f3784727dd6cbb96158c08934848126f87dc7e6368b7b99d2473389c41a9d27bfe62b7b1240d12e0092" },
                { "ru", "738ba862bc22cdca7925a85c3394ef401e81f675bb80c9f47c30f1e38f8c9429798a44bb046289830dae545fb6cc95482abf9c47d1e217247ed490ffcf30a00a" },
                { "sat", "9ca1cfbe3321d026f7081e0d926fbe0dd67f7b401cb8217bbf173547eba4518b3230e7e8e1edf0c968ea38804b42385b8e9cfcfc151d1222f74951dc6e831769" },
                { "sc", "57b58bbcf1ba204343b373f525fecad4f702a99e88ba37835d30a143b20b247788b83d75d438cc60688e0f8704c5dfec0ffb759aef7969f1a82b9297f333055e" },
                { "sco", "7664e8c40667d8e79d67dc1a2673b0dba287fe28dd3ca9766a122c8ad4d001c38022a95fb195dbf4c352cb2eb09c9e02980d430162d3235be57faa3e5dd6d8de" },
                { "si", "dc1f1b458627341b73d6fb1ff0277e9a8586683a5ec0d33c43ac82a027dbc8ac82a3a5a73d208bc4ff61b68c19835fbec9fbeb70a8078c0e6661f91886a2f2b9" },
                { "sk", "db322a9c3fe5f88f7364c1790448752bc0a2c50e426fc1e556776f42bc0037e5ae06dc2a4b4f13912fe2cf6b55be630d2949d306942c83ada6b6f3105946a5a6" },
                { "skr", "844f7546af31fcfb66599a884b270f626b3fcec852981b8f1a256a745d1315acba59209fb5248afe2f075cd8581dab532f5b1a2e28fd17a3433768cc73219cc1" },
                { "sl", "5ec333f62931cc2ec78ca34a1b35ab126d0c6878cb18f217f6404167d5e608321bfb235f21c1200aa13f3754c92fe709645491e50d9c0906ea1740650ce12655" },
                { "son", "ed08d4250ef027b4c47558d1960a92511fbf249ea75f0b9125747b71d8560e5ad90e88c3a73030d3c62e167015bc68686eaa52011a73d012ebe2310c2eb61be4" },
                { "sq", "c30cb365fdc94d862277b987ce77d5c22086a668789db7e85294b3484c281e748da9a5d276242f4507dad464fd775f61726f61d43a386a418bfbf2645aa3418d" },
                { "sr", "0afc996f5e671f562e2c324aa58dbabf1908cfe98b87cc22c507d1aea74db188fc0d20de1f5f3cc7c342d8a512a05472f57d01ee4ec7caf6de6c4b934570e082" },
                { "sv-SE", "631c24f6ba194335d1b382e813c3b03a0e00df07f265d63f7cb0fe55c1c84fb8e4d7e419bd0519bbddce11c4c8d8a06e60dd02b404a078b6e5efbf4a4e356350" },
                { "szl", "cb4ceb49724c1989dd3086b475bd7f2114132a0b13aa82c89c4aa55fbf027e6f2dd6187ec7cc313b70a2eaae6106248eb2bd672f74f12f3f0e66d24e21125bf0" },
                { "ta", "8e388144125c0d86810a52b96751a0f69d0604c4177420ba36e6d4d103b1f3c1cbe26e331743fb6d7888982cf328d53cd0727848f248f19306d2f7c6fe2321bd" },
                { "te", "21cd18dfcd41d1fb17c0af81f225e2e699493c95af3a25a4ec518571d8ae9898a9f62faebee9973fc3c612fbf2e538c3b8864be8098d534b7532f2d37e27402d" },
                { "tg", "15b82634898a3bc748032d592fa2ca68d59ccc78e8c012e278595dbf38e157a051f85c4c8ce1816b155c4ae981484c2a7c8071ae225879b995d8757333d86724" },
                { "th", "60a14556967277ce926cc0be4791d8784c87fe36e4c9b42437f700cae24602890b1e117d5588d9de651f9ab20570fda5d0d03987391b3457f70c570a864e3a07" },
                { "tl", "95babed10aff474d9618d01e7813fdffa8fc8bebf795de94d67a28e073c19bff4cf054f49238d656fb4f05d643973d6eb4443c03ab32114aefb8febde305a56d" },
                { "tr", "1c370dd00c5fff82a7fb1947083654e08ece4e570f09ce85ffc8558178d5b9c2169398f6a278a9017153c6298d1736d6d7807daa8551246cfc3c98ca58ac866e" },
                { "trs", "0cb5262d85b8f05b8fba33b379019dd10e9ac776deccc75429bb30fb83a0c2f05f40d85be181fed9f109b72c060ce1f45ed6e091266ce9e14f5ff62040034427" },
                { "uk", "f6edb52d3f411c00766e76e32c303512eb69af4582c560a73cf38ad4e81a15afd08175d58c6a0a61eb7e076d40ba8aeff88603e7eec8a871dcc66569f80f223a" },
                { "ur", "03041a3d167a68f197628c5524e0bdacc2067694abb495ddb283363f43cd6a54843c4f436c33cf27c7103dfed873c3b4271e9ff1d61c2a03b6ba69033c21e052" },
                { "uz", "45cda877d5ac36ef8914145ff1f04b0cb11029187d1ad798904679598bf10ca34ac2ffb504c1f6a0a00cbfa14bbd51ac4a19f30b9cb21e98b539cdb0eaf4426c" },
                { "vi", "0fe2b5e3d029854e3ab812d4556ae90ca45a50d5db39913b6f1aa436ab3e7beb9d30bfdb3fed9872b46bc514156107035be7169006e69c3d3628277a65e25b6e" },
                { "xh", "8905935602942fddd43918e7d425a0f372137ff1f246c0dc315398b77655f2923e7f1ef24de05db6dc1a70640aac9a1a98a0ffe6368ae4f6b7566e92f6cbb1ca" },
                { "zh-CN", "faab65d2c48560a081693021e8a321ad17f853f64134c58ef54da629731f01b9638c04b480aba09ab5f3a391ea054811fc43bc870cd62130ec8c2dd9fd7b3317" },
                { "zh-TW", "1a512d730f3d15ffd1716e5eb6a08f9d1aea58897f2ad71451a374792f6320944ad87acc6e53675ecac3aecdfd382fcc9404d51f762d4ba8c44e5104d419b307" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            return knownChecksums32Bit().Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Firefox Developer Edition (" + languageCode + ")",
                currentVersion,
                "^Firefox Developer Edition( [0-9]{2}\\.[0-9]([a-z][0-9])?)? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Firefox Developer Edition( [0-9]{2}\\.[0-9]([a-z][0-9])?)? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win64/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma")
                );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "firefox-aurora", "firefox-aurora-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox Developer Edition.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public static string determineNewestVersion()
        {
            string url = "https://ftp.mozilla.org/pub/devedition/releases/";

            string htmlContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                htmlContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox Developer Edition version: " + ex.Message);
                return null;
            }

            // HTML source contains something like "<a href="/pub/devedition/releases/54.0b11/">54.0b11/</a>"
            // for every version. We just collect them all and look for the newest version.
            var versions = new List<QuartetAurora>();
            var regEx = new Regex("<a href=\"/pub/devedition/releases/([0-9]+\\.[0-9]+[a-z][0-9]+)/\">([0-9]+\\.[0-9]+[a-z][0-9]+)/</a>");
            MatchCollection matches = regEx.Matches(htmlContent);
            foreach (Match match in matches)
            {
                if (match.Success)
                {
                    versions.Add(new QuartetAurora(match.Groups[1].Value));
                }
            } // foreach
            versions.Sort();
            if (versions.Count > 0)
            {
                return versions[versions.Count - 1].full();
            }
            else
                return null;
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32-bit and 64-bit (in that order), if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/devedition/releases/60.0b9/SHA512SUMS
             * Common lines look like
             * "7d2caf5e18....2aa76f2  win64/en-GB/Firefox Setup 60.0b9.exe"
             */

            logger.Debug("Determining newest checksums of Firefox Developer Edition (" + languageCode + ")...");
            string sha512SumsContent;
            if (!string.IsNullOrWhiteSpace(checksumsText) && (newerVersion == currentVersion))
            {
                // Use text from earlier request.
                sha512SumsContent = checksumsText;
            }
            else
            {
                // Get file content from Mozilla server.
                string url = "https://ftp.mozilla.org/pub/devedition/releases/" + newerVersion + "/SHA512SUMS";
                var client = HttpClientProvider.Provide();
                try
                {
                    var task = client.GetStringAsync(url);
                    task.Wait();
                    sha512SumsContent = task.Result;
                    if (newerVersion == currentVersion)
                    {
                        checksumsText = sha512SumsContent;
                    }
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer"
                        + " version of Firefox Developer Edition (" + languageCode + "): " + ex.Message);
                    return null;
                }
            } // else
            if (newerVersion == currentVersion)
            {
                if (cs64 == null || cs32 == null)
                {
                    fillChecksumDictionaries();
                }
                if (cs64 != null && cs32 != null && cs32.ContainsKey(languageCode) && cs64.ContainsKey(languageCode))
                {
                    return new string[2] { cs32[languageCode], cs64[languageCode] };
                }
            }
            var sums = new List<string>();
            foreach (var bits in new string[] { "32", "64" })
            {
                // look for line with the correct data
                var reChecksum = new Regex("[0-9a-f]{128}  win" + bits + "/" + languageCode.Replace("-", "\\-")
                    + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
                Match matchChecksum = reChecksum.Match(sha512SumsContent);
                if (!matchChecksum.Success)
                    return null;
                // checksum is the first 128 characters of the match
                sums.Add(matchChecksum.Value[..128]);
            } // foreach
            // return list as array
            return sums.ToArray();
        }


        /// <summary>
        /// Takes the plain text from the checksum file (if already present) and extracts checksums from that file into a dictionary.
        /// </summary>
        private static void fillChecksumDictionaries()
        {
            if (!string.IsNullOrWhiteSpace(checksumsText))
            {
                if ((null == cs32) || (cs32.Count == 0))
                {
                    // look for lines with language code and version for 32-bit
                    var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value[..128]);
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64-bit
                    var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value[..128]);
                    }
                }
            }
        }

        /// <summary>
        /// Determines whether the method searchForNewer() is implemented.
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
            logger.Info("Searching for newer version of Firefox Developer Edition (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            if (newerVersion == currentInfo.newestVersion)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if ((null == newerChecksums) || (newerChecksums.Length != 2)
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
                // fallback to known information
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
            return new List<string>();
        }


        /// <summary>
        /// language code for the Firefox Developer Edition version
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


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32-bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64-bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
