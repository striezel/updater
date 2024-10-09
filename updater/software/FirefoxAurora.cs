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
        private const string currentVersion = "132.0b5";

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
            // https://ftp.mozilla.org/pub/devedition/releases/132.0b5/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "7ca598117649cedcf2e610c2de24bc8e76c31f9d3dfeddfac4b8efceea0fabd62a25b34b03e17043ecf76f07d5944a618e166a4b2681774e9b1fa21f2113e2d4" },
                { "af", "aca0c96b3b52657c0382803934230a9ccea811fcd4ca1b4a40195125dc3417c07765f33b7fad3fb684c624bb28de636aa6690486e1e2d1b852f7e6df6122b88f" },
                { "an", "b843cd0a4c964401d9d1b38032be44b7e88c93dbe97acabd9b738089fadcc085a0e8c0ec91bdd96cf19ef2f4b4511b42e16cbf679d91a38f8c9d72f2db1e5e74" },
                { "ar", "df45bbcc6392be4040bbfa04efcf4e614a0327c7f0aed8858f2241da35df17520ef24520f9f267c7fca4ba282608f7d1fedba2d508874e8c831cc40b8cef8cb3" },
                { "ast", "9fcf985aa95a7298f9707fb28eddf1c6f32bffb851dd8ea0b0ea32577331bc5a34cec248e8fb5261c99b9f32a8f4cbfbd3aa3cd88df43fac1a59ffbc30a63540" },
                { "az", "8090d60dc3a4e49005602e029c60c23d9cef3273a5934e3efbf67e970dd105f91f434b710fa0207b600be40ed5c60e04bbfe340b77fa97ff7d9a99b74a69bbba" },
                { "be", "7b66714645e5010abe023416fa1392619d382297f73ba9ad6e4175bea430149b5ccff2abfdbdf5c460e849e8c61307085aa2896559a7079b29e711a267cc299c" },
                { "bg", "0e769c0f2e7ce2b565b91806f77a92ed8c3a0aa8203481c720d9b0e0f554ae1d58c4bf2d14dd275274c526cfccb0001e29ffe1cbb0b075f56f1be4bc90e8967f" },
                { "bn", "6c5688882cc1c389992e70f3103117b3c48eab656676a62fa6f78f52bdffa2bf286c73ecac89691a383b5b0537c44f6f7c34dd04c198d53eef6fbd508f29e7cd" },
                { "br", "4d65379fb2c400aa99d54798b14ba96e31f08a9eba50a2a53b696f620a88a63f0f7dff90c9350979996948de0a3e8dbc7986944a9c627758dc6f63b108050968" },
                { "bs", "52469bf8b84462e0a4e4eed3723abf8d77de9f380ca17fe1b2a88fbeb699e3095bd9a28c60837073c265d8c8824fae2de9c2ad03aaa36196a28b412a95b7fb52" },
                { "ca", "167560167b697a9ceb1993459e8606cc7776ebfab6ee46c3d91d9737b39ad032dec958454ac6b76b2cb98af039d2d03819ad49bfc259f3a37ba947ea93194da8" },
                { "cak", "97589443a83d1a05d7a67c2482ac382d2b1e59ed23803e746aff8c28fdba044d21674bf70b8cb7997af30d2d2a44156ee182ba4aa45ea76740109cbb648ea13a" },
                { "cs", "2c11ceb47120a7aa1f79193fceafe3767705bba9cbdb9a5a950465fe35e06aa95c65248b22354799e8cbe52130fcbd3d55a35ff9152f2b96bb87c53310e98847" },
                { "cy", "3af71072323023470a08f9fba5fcf08e62a26ff86de3afcac02abd4185a638223022a5d19f38138c6aa6c4217db395ab7dfa51690a524a88d4d69cacd368242d" },
                { "da", "4eeae7aeb760f76f383d67bdad410307297d7349556be6a9b9827de0f0921ca353ac270f87739e60e9247792e7da62ccec52fc4c2426ab334ee9eaab40ea5d85" },
                { "de", "d140fe2fcc28564c60d3377d108f6367cfc38503442aa8d9961aa12193727aa848d701ae595db95e514647e4cd49776c2bb68f88acaa541a28f38c722266e243" },
                { "dsb", "b9f4d52fc0dacf009b15e4753ca9531ba849873b5017b3ac598b874ce6ad380b409da41857fedfa015606b0e015433d1ad5bf90e12f7bcd82278193b0fadd254" },
                { "el", "5f06d4f2b4c071469c60474b5afa9fd2f738f41fd6528b514caf888af8b82c350f669b30bf1c2d65ca509198e227dad4f1f3da00ed9fb73221e695ec549d1950" },
                { "en-CA", "6f9f95ec25614e8b3422c77342e07e50fb32531a35b061117a13c2aa073e85a86e22217e88dc54cc4b4f9c750a39f44289b99a5d200fe5f12165296753ab0235" },
                { "en-GB", "d6c2a4bd7feff9671bbe71731e8b5bc090b8521f39402ec53338ca8ce4ec4404f0b3d83d7d9ea0d33635a18f97eb010fe5fc57ad416ef307f3de44671303c796" },
                { "en-US", "e5bbd51b0fcd175150e06c8718c2dfe7df7f8e7f5a031f74762c4d7da374be24e7f448b20b7f409f10e8f7e663e84386adcd9589776e60ff2cb289c2ad5cc2b4" },
                { "eo", "59f91bfbb76917e6d0f833309494d9ef61984b9e96d6c4cfa2736b12c1086b38a5046bd7e7161a7f5619dce3a718107a5cc31b3ef52b2e5def9caaf2b5a4c6c9" },
                { "es-AR", "8dcf54d9444dcd980c324909996f0226cd15470950015514dd2b9eb73d1422b46027a7cbe4365c51dd5ca48093d28493fd9899e107a403a23cd85da3a4c72836" },
                { "es-CL", "1b7cc87f59981ec139e21c27cb1a58633b5a1d90eea69aafc7b3e63e7fe035df76cc848160cee6f7de7f928b4f1e8fb5fee32575a62bb5c9166449f82ee9c727" },
                { "es-ES", "59c717265c848d330c9a57c817ad693a10fa5ea728b34cf35c9633a4338213256a687d88fbca040fd755d16c682d9e095dbf59c60db0ce5821475f3426fa1e35" },
                { "es-MX", "ed6c974ffb0e30aed1992f0589f863f3fd9be9a83e1e887e9c759252d50dc0ad993724fb2acc7f83c9cac3b6eedaa7ec277257664d8dd2f634eb3f8301431687" },
                { "et", "07f34e70074ab46df5cb82cf0b989e54a26b397fb594b5a4849b388a2cf167d72a8c0f7978771a62b572ef242a93e528d1c8d8e0e3eac4b9a7e25d85aeb3eeb7" },
                { "eu", "4a25fd5dcad5dbfe855a467ad15ee5a52823a3898ad026a9e73c4b296ab615f5a73a4e317bb47487417bf77d40172608822035c60adc834ea3170c612db90488" },
                { "fa", "582484fbf23fa49edb16db4b8f2f93dccef4e31795144e9dfd3b643e70cade8835027604fc1113e4e62b80cd8b1c67f3b00942a9ee8905b094cecee1141e3cdb" },
                { "ff", "04c1a21185bb69c2104b195c5c42a77f8e1b249dac95a0cfcdd6f4a713ae0a9279e265fb9106df954ef186469668e2a0c76ab7fa033850aabc173763e764abbf" },
                { "fi", "a277e28f82502d7f4683c24012de3e6d39ad8f3fdadd6e59f5b88cd56656700e4421c1ef02883972755d439173943f65192b52561eab90763dc9776be03f1091" },
                { "fr", "3b136f0f43c526629285fbe959b202428ee7b77ca0cb7f1f3e5ac7bfcd6d3a115ea5dc4f85c8a208246444ba6a04d32a4cde88869f4e8de6cadd749918833842" },
                { "fur", "670373003cdbd15781f69e657f51ebe5b11f79fbc2933c969c80a0db8265a6357a63abc71f5b9311079e70481d67872903557fe91dbcef44b2ddc4c1ae7bdba6" },
                { "fy-NL", "784c7b8e884ef37b0de92e32690b9dedeea4c18f9398ac42bf86203cdf548b368a2c07aa764b12965df3887356bba9f8b75cb30ea5609a0df1c91919a708bca2" },
                { "ga-IE", "95696d6abfd60310e23b76e0b347a6aac4a661bed41d014cfd521a60883828c9e96225c897539802254957d4dce9e359ccf93f6eb4178d7ea5c4b591d4386bc7" },
                { "gd", "7b67e4a69ac6f2e2ce92f68a44a93263863cf2d80d112be8d65abcd271d2268fbfd54abeccda7df77a20f532c3cbfc29c4ce13f64eb2f81d1593b8abb47abdf0" },
                { "gl", "82dcba10a81776f548bf3417320fb001e5a575a2a3231961f6e83dbd50b80e913f19faf6569286530ed6119ed15a4cbd67fd50169c114613e608f146a9da6657" },
                { "gn", "5bb2a7af0ac53005658c83c128f0e63a6c0d638823a5f5272215b89c2458d0b3f0346c000f8b6944510dbbbfd63f4bb014f0d5515f81e800ad55efc9b2370f45" },
                { "gu-IN", "62a2e37e0e1c1abf9402e7dbd1b9e7a637c58303d32ed0cf200e63565c046587b2c3748c18fa4163d3ac5d68af8c066070e901e800d94f4706c3ec150cf67ee4" },
                { "he", "5d836d9b2c08a7e24e3106831bd0aaaa96ff55686d3cc5ddc0b581a51a4308983287f3126011a071b53e17eec7ec11511b135ccf000e9061bbafda972b05fff5" },
                { "hi-IN", "7afbe45bbdfd2a9dfe8726b5b49dc94f65bb406edeecf0e0e7bcde1bd12c571e8903587417a7f21323a0e21996a9f628984c78c5b0719e3f9b97288389a5e1f5" },
                { "hr", "a6a97483e91217b7fc218a39132af96a09d7f0236a560d95b237450255bd13302f9b82fdda5c29a9b96df6e86ee67139d26cf0c08439da943b477657c6e4ea84" },
                { "hsb", "1467b2f3e6d4a19fe35819b850590831318b4016ec0fb9415fc1b6fea53041fbac0215f4f1693411d6902d33114e0cd796ac802988bfd27c695ed7bbdfd609b7" },
                { "hu", "854ba4f8a42885c493bb2f6aa7b42cc66abec0369add630419c044c55cd94a04df643c498a00f004f305ef66d8dc80214fd14958f95a473e341e8a0ecf1c6df5" },
                { "hy-AM", "fa337b7add22b5d2a54ab7179cf0740fff5c76e027aadbc1f530c2848fa0ed36bc1d13d4d57deb66a4899341b74ea82ca141b9de60a63c550ca1e01da8c5d21d" },
                { "ia", "a6240ec41fbac953561babaefc32d2b6e1c635796c9aa6bcec4a68f9632bbc6fb57d19e4b34d0ef3b891e5fcb1f28d4f574650f2ba827ffa230464419b7b178e" },
                { "id", "df0eb2b6cf310a8b5a0e0e8151593c9057eb1b266a107fc0494659eebb014c1348be83fd9118dbdeb7e531a79c2b076c759a36f3a723d7acb0d8353943aa0dcd" },
                { "is", "fd53b5def5ecfa9fd9c4ce4707581c669b601080cf38975126d46567d81e8578ff325c44b34a9dc11280af69b3f1ca7c00d80987e603c532a75c31b19a5761b8" },
                { "it", "21449cbe3714b6b06ce0cbc2048b4e11ef99661978a1b3a25d705f7ebf78542e77eb0deb7c082c859e4543e3b726b29890221fdcc6d830347eb12b9a6a8b0d5f" },
                { "ja", "713c98b8ec1337f14953285a642576ca83951ceea40eed2bae51cc3271fc5379229dcab6cacca46bd9d4b7c6030fdd06a018c85148b4d5f45852391ff9bd49a7" },
                { "ka", "cbfa5cd9eeebf91b211d5509a8d99e0d52b2a8dc12508aaedff9060d7f2fd30f6f232933899fbd4c4873f09ea1ea843c199d15b7b675a58eca219561487479a3" },
                { "kab", "b1c1d348a1d133b1158c7cd96958ecb0d63792ab13fa34e93a0a9f6da9f58be3c49be36584fe4cb7bbb94d71baeffd90c42ba61592ba10e1c26a1f1e78a38ad8" },
                { "kk", "7d16a76c413c835c19cfff92398ca9c4ebf0a9147e83cf8662749d0108074464ea35901e0a2a3eb10eebb1578cbd8c6df1e0698ac808ab57efe88b0e763049b6" },
                { "km", "06aa1a9c8895ce0ed2fa88856bb7dd5d54d2efb15e82b2f1d51f80671c2f731bea4ad89f99c6fbbc2dd01345d4857e9c930cf14ad15dc88884df836f456934d7" },
                { "kn", "9e63d322d9f2dbe4607dafa7f2619218ef08c8075b6fcdd23ecba48a09e496058a6b0bc5df1d73ec9346f22145c24b7b6cdecbe4c5085d84fdf2a05a84eb1e92" },
                { "ko", "6d0bc3df8790feacc7e39bec84ff4a7d1725e9922b4774288f870617d353a5189e853953e2deed2467953fee95b50193a90af4585aaddd37918f5708bf585b2d" },
                { "lij", "a362e8dd684ac10590063e42f4a1b7a215eb5caa9c9a30844c5cc6f1e43a58ce2306aa33af896bceab33ad4a1f528736cf7561eed9b7f48fb63ae912bf27e4ae" },
                { "lt", "3ba185ffd33d5da3e7d98074a3bff762e4699839000826ec6cd6259e988a0dfa115add76acd9480c6d28237b2f0e8067e93894d7d1d65edae3707a9ccad9f11b" },
                { "lv", "dc28d327e3d7662f0cfd3beb6384dddae4ec37f2a55fbc233b7fe4f790ad85c2c40b7e2a408914fe3ecc0567a8fc8609fbbd4c1e4b77e78e492ed4753e687e79" },
                { "mk", "b31cc251a66f91d3eb77787d54940d706ede7e472f2d83ae828b8387215f1272ab20eb661b1b05034c71ba985d913182381f975abe008488333901b2d235e2f5" },
                { "mr", "fbe97f88513e982cf62a6d4add727b6a0a61ac6a5fb07d98dab08aa8ec3b4b70c5653aaef330c0c336f1d9ab49b2a908a6753577c16122b3fbc0abf69183174f" },
                { "ms", "f29c6589502bcf42c1dbd5ea84d9d3a967ab4c330676be07d016a1db44c36d0f3a8ddf0b1a5324c3b077ebee05f928e8bafd825c252a6fc50c6e0010c5761720" },
                { "my", "0e93b1ad6b9bf5418c5e0d392b66cb7abc5d38a602d99a446e4c7be241d3b13710a9154653bffadfa3575afb0fafc49903a2238a2d523fde3689ea342db0b1a9" },
                { "nb-NO", "2b7708d002b01a4a751f112207c33d38ae37184ada4927d676a2e5384baac04c9774e7967635fa1d8a56c75f780ba0c4670aa83f902708ad7b91c1b23e052899" },
                { "ne-NP", "cb0798d08197bda8bbf2b27beabf18587170c27d5830b0b322c842d9c5b4d6a7090a2622b20bb415a6a5c2c05ef93098aa907362c03b8cd9ae9ec319b36cd9da" },
                { "nl", "933e0de35c3475e5e159530a2c3e773a61e8c63d3c4cb46af9747dfd5fef44899d3c71492dbf2f8cd078f8a795e49bd8c489769eb095e6e42af8d95cbcf87b81" },
                { "nn-NO", "786bbf346858afbd4b7685e497abb76debea3f5055e29792fe409cff7d64cd8da766a2637e8c3384f1fda829565eafa23a66c30d158fa3044f35f01323b6a31a" },
                { "oc", "330192365ef7d0b2210941c9106a7b32f340c9a236d261f9787288a1622f32cccf90b213cd626196027b54f38e44808140d229863dfdb6b5375c00730e54ba63" },
                { "pa-IN", "126b7c44f53a94acd44acd0cf8d7b84e90fcd2e9b6e2a1ca8ffda8dc3216dd06014ab01ae3260524f76ac9e08ab6a046ae5e02167582b70e525fcca35f9e5c9d" },
                { "pl", "1a502a106f14ad918e9ceb0cd35654fb86e558be7234a6dd57af775e20bc949d50b54414182d6a10e0c4d93a218c809943bfecd811c8c74da44c037c455abff5" },
                { "pt-BR", "4efd944496e5ec1f31cf5208dda2dc4b14578de8f1de953a6c9e7f70417aa1e26a0c098d77029243f25575d3418819aa39e4594159a7f59654698a5d64ac22bc" },
                { "pt-PT", "2e0de23ca28adb6c119fb89e0b32eb3f0f5c5d1e66f2e8406b1a74c7ed496dedf2aa0b18c644e72badf916a1dae87515a3297cbabf11bdc82849e0dc75fa8f99" },
                { "rm", "93bec05311363b466b8079dc2b1d2d59474ea5ee3096105cdd01b021f85473334d1f585fc33b60ec3c4d4067f4adf8b598a3282f92ce782fccaffc2454d86ab3" },
                { "ro", "fe8b468737a800da5c84f0354b9e99839a9b41860c134aeefb5e22abeddb0aa8338de46faa4ce4f473431ced3e4203a42b70ab9dab68a4703201a30833c4b7cd" },
                { "ru", "038fe826e04115bcf9d04bddb88f55c5a4de9b72b087bb9d0d3d9b3aa19d4f5ba1ec37b2df8458ff652d73b52370f97bf60da03a6d318c09158b1dda61c59617" },
                { "sat", "ac2e4b2d33c4ffa4b963996ae25f11d37b758e5c8afa29926bf318c7fc1e733dc2dafa2b807545c5782c0f8cc9431ed88e66270d2d38b25914ee51e0cab23305" },
                { "sc", "bb2fd768515e0997f5ead7ecdfee9d7c31036721ab65a440a4692abfee7ccf513da87157f633af8a2e38bd2aa15074dfbf0c6b8cf5933b6a52273fe8835e6513" },
                { "sco", "c3a64ac8806137518fad225942601a6174f5ad70c921a4ff61db74b528d6e2f1ff82dcc661d451046b5fbf2becf1d5aed96a649d81069cd18f896df35d3f1cf0" },
                { "si", "115d6339846e79724d6ec6f7d5860bc317c560c0085bc058e751dd9779a2ac7573aec2ddd91d881e0bda87b8939bfccb3306379d5191c18906f4fc78ff6eea2d" },
                { "sk", "968af0bd372f5b970cb3c3507cc9194792c6bf5591f1fa00dcca30bf9cef1aacd5b60df4641a1293469a869c842380339b97d1b0183cf3dc447f643d41680340" },
                { "skr", "bfe58cb75843c0c9c16fa47b4fc875cec3bf0b9f84045d034d2c7ab41ec34a3336fe8ca6754993c3ee3297735241ccd59754d229c0a023c779fcbadc3188ade5" },
                { "sl", "f34bb664d976ee3188a2fcbf48b4ba291934fb47debc1d50f7c221ac9b7d1ec107833d5df77cfa5e5499b08443ee95e4e74d5ce96403ba77be974f958061dda7" },
                { "son", "8a57734e08709ac513c1b8919d3724926ad98ccf0ca61e51f87bd32052f8fdb1d08a8bf1f76e14bac204c124fbff8ad675f359951b6c81586eb8cd8906443482" },
                { "sq", "f89b06f9183b34f7339c3b16411a0bdc60ec98c5e49817c96b815dd54238a4e231f251e4fa57b2b19c2bb74298ca19e895ddcbe9e027d8822094040f6a605b1c" },
                { "sr", "0d696503a08e8b6315661440edf6c4451da2c927c96a328caab1c291f45e4d4a10c6a90b2b70d48692ce7c594bbde6e917a408483212c35c9f05685cf7a8dbd1" },
                { "sv-SE", "3f7b1dfe5140164f027fba14c79473e6eaf687e8e161861eab3b64eb9ab09650afbc71a59ea33d8b260b8cbe4aac4b2a3175d576dba4912d5f2737d3be24fc97" },
                { "szl", "31cff87e334b2a7a4aecf1a6c8498685ab667c8e13796d91f9c32cedcb1910d6e7a080ff62e456d80d874577243764d8bf4dd29c4621766eaf73864f29d105ee" },
                { "ta", "2ee93e6d40bcd35c66ac87ee430b1e4e14d256fcf10bf6d38e4db728bbf2d98c23d2e8d5f968419042d5aaa07745e93e559af340cc1ceda48adaed2951028b87" },
                { "te", "e5d873cedd1c3a6b9873ab5224093ad170f95de4b6873058db0479899778997c55f6ecc60135253e5f5c5cd7fe582f870d5c0200184df775c2a8d1dbcd34094a" },
                { "tg", "1e65acc2222328d35bf468992eb75bf562b6333cf62de25e6fa73f451bdb177c32ae0ac4dbf7fa7c1b94297f6f3992750fdef336ed0f2f6e97ab292e28ac0076" },
                { "th", "33dfdbb4eeefa3eee6a0aefecbc9fca6891cb8c751c79eba8b3ca7039e90ea30a3fc9f890faacbe66bee1ca9638be20cdc5b631239b01f07821d37e74f4b0e11" },
                { "tl", "2cc264af24689f9632c7abcf33dbc73e8af8e0eec087502a3443a6ae48f1d8544024bac2695c5149f01d344259791f66791cf21026e338fbaf5177fbbc4b2a61" },
                { "tr", "8ec16cae3383028ed2590c5b19e6f19d204729e6ff7a1ee6adfbe1eabd2ed3a364b8c64a872ed3e83e67452de87d183b29993a30c25c3a32b1da3d6fb1b8a169" },
                { "trs", "d745e1f1edfe2fe3ef24bb6660e478cb4a607aac1d1e7ecfe6d70941dcf647d2227e0eef773768190e7a966fe6a2087734e9b238b9402d3d3298a124a8bab72f" },
                { "uk", "0438b2898a05a16200fe092c8c86b6d763a2261c0bc57ed235aa85c8d8aaca15dd35fd8818978d3c406e25521ef96da45922f379451edefaa0f4542ac01716f1" },
                { "ur", "003f1dbe6e9d44d5ab04c569a927ab1303ef8aaae5f66c4731ad483ed4cdf8aecbbca10460d7b892881dfee69cfbe2de70e69303c70806c4881f3055e094bc54" },
                { "uz", "f6264dbacc2ebce0d1e9988a2adb9c2eddd0b4597f1214500973037d8116f53b13d9b75504fa5e2e2d4f2e6a1709e32c0d67680d5ed4b45cb6bb30c5dc77cf58" },
                { "vi", "a04e6fb907a5fae3e92c80485d9410f6c6de7878913b7dde8d19078db4e668f040e62ad3149b9729d8236be40b19be51048ec13b8126418518e0fd59f58bac53" },
                { "xh", "e607cfbaf73f27e3d496778bc31bbd925529dc4d752d4c5674985fd181f258698818ca4d6ed2d9cdb732e67f5bd2a298687f1294d3820b29869c2207ec9b3060" },
                { "zh-CN", "d78a6de18846d7e644c3a03e2f39053ed4664d110881a4cd0ac106bdb4e044b7b726fa8f06c03d0ea625b0881d6f58067cce7ff48fb36df279ebfe4e9c99ba36" },
                { "zh-TW", "4dec64ebf2a13b16436115cbf84ad15cf33deafa26dca94c882116421e9d47ab7bfeb6f529b21b2fb928751ddbcbdb30cf19548d14e9159a8ea3440742f21a7e" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/132.0b5/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "7369347c890b382f06f98e7cba4513381ff5769d6759f602dfb0ee4705f8f011ce4c45727f04775e935999a8112cbf9bd2dbc9e807db854ac930aa67f15f3f92" },
                { "af", "58f5afa96e13a3c3d431f49a035048e5fd0c131a3093a7fbd8009c17aa99d6342db4abb99bbb4c97fc203ad25d6ddecdc15bbe09dc6d2349a34743b66e6b3b34" },
                { "an", "8c5b326aeb34b8441dc6988c763ceab3fd3bf8d8ca46e0161ff033561f50c0bed97dc39256d1d14cbc3c3a301804cb7e7d226613c5113a93e2eed76fd06edaf5" },
                { "ar", "62a808d1bf8eeaa98901a32cbc4bfa95b82c8f54c72571ebb5308e452a2903f037375fd497330996a947b086775dd75fb16cdc6417c4be73a62aa63c15bda3f6" },
                { "ast", "f86b2b3e5f29e651b51332988b402d64bc7bf37d974e2c7ba79555ca7ff176fa9a48ba826580243a9697c7dc5d2ce35a74573d24fffaa2076e9c00d9a56f1a0b" },
                { "az", "28d33784445374a1b07b67cf97c6c5023f12c350e9a57f235fb08f25e16345965906abf3a00861d805cdde2b78b14eb54069a212d276d5b2edf31296d00eb682" },
                { "be", "16e451370a86ae6305f0cadc54f2d7e87cba59eda76efa41eb9435ed4c81e1e65ce113ac107856fd1b10998342ac0108a3b64c999e467491de26bee1da5112b1" },
                { "bg", "993dcadf7023decee990cf5c311c562889f9521f5cba3cc03295fa9a876abf12b042b955d8cf0660b5613440bc8855ab3dc7b1cad8bc4188c60aa2ebc63bbadf" },
                { "bn", "74d4c75dbed68ddcf5b57a9e04923af5ce00cca5d1e34007e14cd7c31805f8f17b3c8c3bacd2e1b321d11ad9b6cba1e49d4c94441ea429a2cfae0e2b85596622" },
                { "br", "633a24cbab6c97ccd8d021e4382574def40d3e2a91d7e6227443536d4aee566ca7ad0767a29414b0c8b0455ff695f08ef85dbfe73339cbbe7aa94e87cfecbd48" },
                { "bs", "663a541f05a4959b51fbbad20537302eb7615bc099e265c3ceed64e2979940ac15cbfca151fe8d55ced3dd98da9cd64a5e86035650c91b79a254e34c66bdd70b" },
                { "ca", "6dabc8c91e8e6ed9236d983dbf44ba336b30d947a1f1d24ae6c8a6e3325b231cc8c8f4e0b4f7484cb0bc587febaae572e09e99d48f70cf393b622f1d5f830f51" },
                { "cak", "724849d070f74769e11477a613b001058828b1458a757e08b9dbf1ed6a11c85eec3a5d3efe00167ac20ac60a0a35f6e12ffb20754fdbf5bb26d821ad83980540" },
                { "cs", "331b0de0eeb798edd58f248092b34f9f2b06da8e42dada385e17db2e4af789b914502e6741bb7c4d4e5144c9418ae122646950adf084bd89043081e743eb8238" },
                { "cy", "c5fc91c358fa5713b90010234798fea7e7805f1179b4c1472176947895e382b17e1ea373a70bee3dcf9f5758cdef64243e37ae2667de52119a824f7bd86a158c" },
                { "da", "504daab0649f6e00ae21f26becbf074b0c14deba2e6065f43930a6ac472484602fe8fedd8b94a31e6c3a9a90f0d42eed16ebce85972e4c45763023f487724f5c" },
                { "de", "0346f2a453aec3529caea47234541bb55c8e9a20b577d828a0297a5e71f57b72015892a5e96b4596d8c5f5f2ccb39842ed7abf9a2551319fa41ba7e7ea760ff6" },
                { "dsb", "52fb2f8c236f4888ee363f80f3be2d69bf8d6bead70cc977d5d216d53ba69bb6d9c476971b098562cb787003c134dafdda9e1047256e91429d30cfb8c7f5581d" },
                { "el", "9ade0a26ac5485fae0fd9db25c4e893134445207dc509f294909e1f1ed94e585549b6e7dfc60e5b996166222edb3caddded1ec890a4d6358f477e85a315539db" },
                { "en-CA", "5c3cf4437dd7aa67f6719be272b3c07251a584dd58954ba29bafd3813c981a093a3e1dd55c2a537c2955194c039caafab101481993b984ec0dfc6f864ff037c0" },
                { "en-GB", "97c0fa44d8eb4256afd58978cd7f1524587af591a216619ad2f72b6fbfef7dce86f972a13d53d473dd76af7f0de6be5dd4c0dade7b63d0196c86f732a2fd5815" },
                { "en-US", "87a041ee1deb406ac0a704850fa5a2cb6a704550ce923ce0fc4e4c2241fa946822ab72b7efe88c3aefd23102610d46c3132394a1bb28a097a8238a1fa14aa869" },
                { "eo", "967d3d1d81ad01db2a4495a3f27c07f8177176ef6601e4144b0504bc805e92534f88dae07d17dbfe6559213025f015014007676848425fffa951a5616ea3b9d6" },
                { "es-AR", "4b8f17eb4026c737ee57a4164f910c2f058a7af760eb1f5d54ed4ae9a645530534154f1309943c206b83830ed397f73a0f9714425d2f9c9455450bb1ca0ca607" },
                { "es-CL", "e181e5e3bef7fb29a7218d391579c72ade7f49e61538430995d13b55ec3f7968a2137df10a54344ab075875c1a5cf288eb9701958062c719809e8e5b482475bb" },
                { "es-ES", "03f6c7b666459093cdad5bebc273a3238768358eaf910400c35eb25c870c5c319bbbd46586b10be69f17992fe3290198d26078266b492382d10fd9cffa00a217" },
                { "es-MX", "37e0fcb55f8e694d81f28bfd59fd9344bfdd7720c9f8e0ec1e9a00abd8acd238fd791ff698d504d275eff6c2a56784745e8b7db9c65f48a5482f4fb01df2d38e" },
                { "et", "3baa09d0c1d83800236d0fb0004fac3f6a7c62e401becfeadd65531d0b00b0df77c9a192ba772fee7d8ffb31734189298762f55fd8cbd5388ab0dd966b34594b" },
                { "eu", "6fd7b186ab1efac9b4f0ee8b278c189bb07b2d08b4767bc14b51d96e3c473dc417af9d137d756ddaa1a8bee991a80cb7c28e2eb031ba5594df79f1f086f78ed7" },
                { "fa", "ef1aedf6f46026eaddb000a02cd942bb8d8c0fd719f91368660cb63e3a7e992424bcb09411861299f97239af663f8da97c0a8f64c19054a9877bcb66d45f116c" },
                { "ff", "92802c0f3d823331fcf0ff290ad8cbf7ae1347af8c5dd8b5b647cee9b6165cffd5e1e7de3309f0a7c712b705f3edb6aecd8d93e09deb014bf2dd17879f6b3a25" },
                { "fi", "4702ce8bbc441f6e1cb0bdc6cb2cce832f0de2a981202de887a86c5224c97a1b71c82fd9a99114c49a9240b5dfb1c6aa13585f9c4c7c29a28ffe8bc70d10e2f3" },
                { "fr", "5e4cf1060ad213e2c1ab9b172ca6c9095219e374897c9945f62f100ea9b7cbf6af96843034e05965c860c7f5d243135b173f00bd9e41060a17936794fc13faa5" },
                { "fur", "583f2bb3b9ace84d2065e7a4134d846476dbfb457854c1584143e94228172f1f0c8f3e98e5373571a6675687b3d7eb985607a06130bdabf99e908892fc6f7a8b" },
                { "fy-NL", "bddeb606b595bf9fdf6fc7580b49f544d4d85d50bb00273a88b224f0b9122ad574ee95cc24163bd1d050b0d44e62a8b9dc14be8951e06048bf6bb631a4012574" },
                { "ga-IE", "f941458db5534a0e90f12c8acfdbd322153b6684f3019eb58f8d67ab4ea004550040b31f8bae99f1dcb75fa11e46fe2a480472364a4b5b056d7e0bd888b61fd2" },
                { "gd", "b8f39e3ff2c597742c4b60b2398bca282aa028c0e9cfaa005b5bbde881104d5d5831188be3269322b445a700f345361597063450b57357b4b0d4c488cf8c83d5" },
                { "gl", "839ca404f6b387900775b65e26b7a829bdf83e3c23075d6d11550e27e50be787fdedcd3737bd29be83814df4986c01e42e768d2869c7bbeb295f06c24a089696" },
                { "gn", "49628d535bdfd3dc4379bffdbad9735dff4d3295655be576ac94c3945a4d90f47f2888d0ba3f84b82704a2eb49cc1c7d11db433c39166b1f5a8203c707e11296" },
                { "gu-IN", "7db3e9d95a2ab785b09e46c02430d67ec6675b29766d8adf5848c3fc57c338e1a4cf30970e6f980202efcfa034ac57366f8d4f98f5cccb33a73d0f10ab5bf0da" },
                { "he", "8e0177ea32ac2fa0df54d7815eda3480a1c8625f668ae8e37f277bd54c460c5bdbf9c9da509abaae5bd1351e2d2d837505257865cb87dc97819899cc9f1cbcaf" },
                { "hi-IN", "d741ae133c57f8fe2d42f2676f324d8a090f24e12fd2df30e76937b217a51cc4b4b4ced59cf04fb8ae9354bb3d8ee6cf6f447c0ac8699e5d73507137d2618d3e" },
                { "hr", "17c751b08132b138f955e7919e2b95b83d23a55edd94c50da90af1e3b52fbe10b2dd96afb004197c05c75ba54e3b966aecf06176d7ac03a025dca35fb58379c4" },
                { "hsb", "8305dea1e3d78b36249c04e005f64156784c4f16502090cd944d2077952b1fe404de4a4e8c6aa1d4db0b4d38cf296b0ea3b42832d25193680017b78673b674cb" },
                { "hu", "1801a2a40ae4a812b5bf7998fc1b483d369705609f43db6c4cdd014193cf4ec027fd1713387299e30acdcf3207068e4a6e93ef98a412530131afad1fd8a3b33b" },
                { "hy-AM", "c8e07c708496dc0890321a133990d1d075071f790277cf4cbe6b45fa8a8fd1c4e39d7c24d56ab1532581b465f85d5fe3690a85216779b292e36acb7aaf3b0804" },
                { "ia", "50498300ec7af50fed7d757e835dadf5c4619729175235f88fba7fb604bd937edcaeb55916f529a34f0447a6c462042e269bfdd675823af806b7b23dad64e03f" },
                { "id", "4082a4c1ba197a7f191ca830dda8f368c9dae72216cc4e759590164533d2acd49b8ece227e6e79d3646c2cb35dd6ede1a15cc6ac6bedf1dc1afbe457d5dbe4cf" },
                { "is", "36eaea473eb5272434e919d5845d8f735fba2b2e291e932acc301ce4c92d7dc5878cd731ccf0e828d8354766a02c41d28561c0461f9dffbb91cd4a804a835806" },
                { "it", "427bd7c75e8b47b092475b1f0b9c7c49f8c15441637d27e4efa0fe482201b59ede527325b27e3a66609b2cdd9188767e0c67a74c4e66a57fc529ae4acc35d26d" },
                { "ja", "e2456c59addc13f967a142cc9693ea555d7cab6f19f837f0b932c63f15d1c90e56c95d2ed2186c7fd303a426135adce32bdc85872c06bb6146f2a26e5ad12186" },
                { "ka", "5b751ecd7caeec0fbdd82fd52a98d489e6d2632b652feefb33064af68b1afb18bf6c7eac55b5de98beca56ec07777c34b16dfc9883ceb94880ab89a8c0fcee65" },
                { "kab", "719c145f3c38d560eb2fc9ee99d3dffd23b5bc0c21f87d7cec57dd0593d5627926a05531581c82b3eb8e3d23500354afe894adb53be2d10f623c7b826930c780" },
                { "kk", "c3749d1b40a5220b349aa67c0f692fc432774213f76b43efbd09c4d03076017996c05b46a82906a55c5256909b7844e88017096c2cf911833372a0df884b2a6f" },
                { "km", "99dc9ca61f39ebb44a15cf63fb0034e8c412cad506f30a69f0ab6476c28f24cae63d136d94d27604c4a1048be0dffa52f2532b557b64a79c60d175f4f62690ae" },
                { "kn", "d91b71bdf97459e53371aa2e788f010e42611b7945a335bbb9047f52918b6918ca74b3c6f7c78b0b99da54e081bbbfe0792d4bbb86241226aef4726daa085798" },
                { "ko", "84e08e90e90338249dc5fadcc87f056782f3b140062a845f3dae423fddd46529299ae08bb60a57b6ffcd73e2e52982560acb0079705947c8eb41bc889d4fc340" },
                { "lij", "bf75ab48a7cfb7095d9505f5f10ec0f2dbf7ad3cf7448264fbc107587ddc2bb0f7231d0ce8996d03e309cc5209d0f97bf1160266a38585b4fc29a1328eacdfbc" },
                { "lt", "64275eb0934801877e4ab3413b3b3aad2554ca8bb73c33670f5a5ca9268a79a008a9f059ae2183b64d50d607cbf7306e82920fb5ce98aa0726024fe628d9d92a" },
                { "lv", "8e5c475de40c0e2dc5e994707db747dd15afad0914af749b069d29a376b6b3b77eb07def9142d93070adb8da477f415c3c2b316bc424e275d807614182000185" },
                { "mk", "56f4bd6b27327cc9151c0d902fb8273c84f6a02b2ba808adef187b79d0db4848d7f8582399dca67cce91703c45d7cb1fda8c26a0b855f71410890305d239d1a7" },
                { "mr", "ce9d30b54a71e25f980a54012fde65ddac13fc2818777d96228173cea41606d3e62eb88bb34895d3227ecf81bb8d237e7e27f5eec20bd577b38dd8e3a59715c5" },
                { "ms", "0523bb33138fe19c84b613df3eb7c73dc585f5cba475f7feec46f01bfdf8c6f751c03014734e3aa55291ace5f4a327d738538e4310df3077e5707b98c9a95f9f" },
                { "my", "80e14a66a160b22721c7ecde725e1962a071202a1429812d1a916dfde4aeae3f20a96f30a33d2206925886b5079cf4e48d93564792afb6d39ca2318455bc6127" },
                { "nb-NO", "5a8b2cb433779a13f37634d498882d0ed8a69d82281a2548b4f05bb4145a08839d6c966a8a8e0075d3fd5dce8044b14da1a5ea5bf4eac8e92f3054cf2134cfef" },
                { "ne-NP", "0c08f1d7a44979971e19bb14fd2dcd3e8773a565d526d6492ccb754942e0c39f754637ee1442a3c275ed46e0a892ab944cb3a306a699de4d838cadc907edbe87" },
                { "nl", "15179cdecea3eba43832a916ca5b769d9e5b60c1f586f5250cb739d3db73b0d9d37f67582b13400d1a791fa051dd79413ac3edf9a2c1ad97f175ea6fd8e4b399" },
                { "nn-NO", "734bb5e046c26e93189007b08a379d1ba52251d7792e6cd8ecfe58c64c3039539cdc0baa33af649fc9c34659d85ed34c0705dd569bda26353ffbf014a4d7ef97" },
                { "oc", "512bc79927aad4b9707bdc61b6ac8b192e7370e57bd070b5befc39ed9919df63589ecdaabc8798e6336a5c4a558f465ed780bf034432099b872621b97887ae90" },
                { "pa-IN", "bb41b7a364685a2e46dbe6099e385e91462e4e8997cc322b506f47cd3d5344ac80d1a0b70ec2ee656bf0a28ac822c1e79d5d7826efd868e30c3a585bb3eb189f" },
                { "pl", "ffbf0b53669e7be5147dc9c964c24d82095db10b854b718bc8ec04a5caa03a3a76dd7860c392f72651a68cd81ad4483671ae2f48a6c4a97f12ea31bb31fcbc95" },
                { "pt-BR", "1c92d55f2970c26363c149d29068bc37cd3dd21b4b9e5827a5999f5fbc116c9f2c3e80b96cf47a2c88fdf1eca67fc8cd0d18faa1e420cc83cfaa6bc31d477956" },
                { "pt-PT", "01590493cf741466d8a1f85060ca07f9cc916036b1c685b786e9ae763709c0dd6d762b33d9271c3bb5f8af7756d2ba7112d5c22cc214a6b1075ec39054fcafbd" },
                { "rm", "e214b75bb11b2070c6dd63c0707d6afb95f8711adc19ccd6c559cf35e9d27c4de1af9b164766a92712bce6a060f417234e59a1ceb672f8406bc219bc0345a814" },
                { "ro", "e582825e2d08948e905a303f1341652bfb6ac026a8d515793d053c8a416cda9c0c52bb0545d5224e290bdc188e9b0730bb59eff51a94ccf7d85ba6dde25e6de3" },
                { "ru", "8a55c23b438247c3b6b3a84ba98d433186241dea51a7caf7301260b2b79b537ff50559ee966927b388c2494ef016fe9e92f97d99a9148b1e3603a5f05d7057e9" },
                { "sat", "e6c29241c58c6347e58182944a7c4ccd855963c52caa24746d1e6bff754181d82eaf2597b70369f52cc2884894d2e77c612f4f81f3f35519d0f4cd614abd1413" },
                { "sc", "17194b8c34edf1606144a126e74d3d674f8f72041e94747671e6b910a640be91f0721522df31b81d6a7bc5371871d8a971da32446438c30d214804dabd10ad52" },
                { "sco", "a6dad4fa39e95b57b8be24158ee1c5f2508574dbaf88f2c7367e474870445c351a7eb6dfa12345518e01478366e4663e6bc9da2649a1d061586e7315d26d8211" },
                { "si", "eb0ad69b33462b7f879d6302dc6b6fa29f06b3b4b9834bf1db4ff40120058b6ead68e3b32448489c027ac0d6102c60444d799211346944f359ffbc12d0694146" },
                { "sk", "aeb24f703c97ded3c35c1c03ab0db9ef9b7f8be0a8506094c2ee4d2a6893813c5fd32012987e58788d8b81dc6e7d16441bfbdebbda7fee3b0e62333aa1dd6ed7" },
                { "skr", "10a19e70ea12177d51dbda7dac0e401d1e6dbf99d815506188dad8f4a5abccb4e24b4561a508993e9b0bc3e0bdd6de9d05029c370767d5ef46035e2f72b15a88" },
                { "sl", "a3a4ad285d2c6399e9668d8900bad066ed97dd971b093ed4c6784d4570da2858fc43bf4e3bc1e659bc22f5fb1b84061bbe8f0608071bc46bee7625a3c41c1b0d" },
                { "son", "96ad2068753bcb3be85401c7f33ff5082d899b326b3ea5639fe85c55ee84b9036b225a349dc9458debd749542eb0d94ef951dde72c44c4699cf55fa4e78b9f3e" },
                { "sq", "6afd21fc2100f6c9660437f33ed2314362813e75ad8a3ede896580307d3be7756a77f85e31a99d516f742ad310634729b1dd77bd80648c276f323bfbc23ee9a6" },
                { "sr", "05721f23856b3e892fd547fec48a7360c4a3f16ccc49060741d36a7b91d36144bd52a288554e914daba12f51022a79fd52a46b01d95d8bd4010fb51a3ac0d92d" },
                { "sv-SE", "9b1955418e8d810e8238f4f7877d9f72248b18aae8a0750b4b19de5a6464ccdee132e3f9144e172fa5ca4fa00c6a093f82c3d3d36d6c8e3cf70cf0d011bc3d61" },
                { "szl", "fd55faf948a62615eed0a20df3e6da8454fe06b03d3253f20c4d58fa73c29214c69c3a940e64b71c39c2a3174f40e28dcccbc4d4d5636bf7c20beba304c463af" },
                { "ta", "e917c1bb889ef616c5077dbbbd3e7afe1f6afcaad2101269e1a70d83908708ffaa1f8a43edebf284e444e21e9a3cda1a36e78829a5684318c585c7a14cdf4061" },
                { "te", "0d2c525c3c56204b22dd1584141f8f7478665a1da20f17774b142c6415846e463af01068a34e760dd1acbe4263460f9df76208a1a98c0838281ae40fde47c8e2" },
                { "tg", "8541ab5a26978b2ce620349052bf6e0e2cc5af573eb9e031312f258ecd15edc1e5b46ef8c10b8650bfffadfde731c0f2fbe7267d0140f6a256f075d34c4ad8a9" },
                { "th", "f33b75fac334523fd2f04aad1f075fb2d526336fed2fed42f8c3842c2510c1bd76a0cb3629b3de8ff01cd70d00145fcea5376087445851e0a0016177321610a0" },
                { "tl", "27cda73bb5124e8e40d993c2efcdcce7a407e9561a322fe98965baa6125009694303059ed7f6fcf1a3056bf6d591464b44858e1be9a2f352cd4c25ce320f1e22" },
                { "tr", "887bf1e7e0d4f6321a8c796f30187d2fc675589f679aad27864c02750d7df12f16d59105268b31128ac0ba349054787f440fd6eef0002ed1027741b8dbb4b6f0" },
                { "trs", "d79cf0972b9914441d30ec723ee07a05a29cb1497bb8eb65345bda9a45615d6d8b6cf4d494dcc2c557e95d21d142be69b7d9607c5278594831e88d9116235167" },
                { "uk", "67a4641ed374b2a96c5279dc512aead57a5739e23f49c741e90f898acda104c853337fb01ad157074ba6b9b3bf55aa8546a5e5c137773f4c736969e9eaef3d32" },
                { "ur", "3d9c97b8cf9240d60e2a3f388795a2f78e4241e1e9c7309a2f21e7b13102d4ba354d0cc539b2a1c0ae26c96347dd0d8c726e272da8df45cc7c9d7561a5285ca1" },
                { "uz", "67ae6f63be1c4066040df061ea04a90d08468c39a7f62a342e1433e8802d56036ddc34dc9af03da2e20ff59b55b42a6a608018a136020bef53a8b182e5e01b35" },
                { "vi", "ed78e14739599ee09352540950cff4174ddd998dea31623b539d1718daa95aa042d33a0c2529de8b27dce432aa05f84c0a804f1e8ab8c5b0d78bb1a5d580b9ff" },
                { "xh", "aa61ca839ec936afa401b9478aa9119b4dcd82e5b74f3b96b52ed485582e7a2f807f2c47d1b830e3e9efaaa5b89abdb22b1ea2fa3a3a1f189f5498a676b5d704" },
                { "zh-CN", "4f77da8de134ba80edcaecf15b63934d93d8c29948bd34b9d6b785b64fe4f3a7a9d35d3b93600fa8996e953d034c6d5d975a5248c9dd6a9f0697f805049e4196" },
                { "zh-TW", "c266fccb29997d816c3ce813c1b7d90e3713add3e9826f05e439309532f4a3c4051e22f8cfb91b79773ab4eab34efc6273b7345ed886a7f9aa39f3ed9ffa21c0" }
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
                return versions[^1].full();
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
