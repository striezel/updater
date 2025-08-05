﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Firefox, release channel
    /// </summary>
    public class Firefox : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Firefox class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Firefox).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Firefox(string langCode, bool autoGetNewer)
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/141.0.2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "413c08ff62ed2051c48d8c190e5606ef7b2f6e7dfa42396bb80d9e9d8111474659d89f276f625427650f4fcfa3328e329e2e69395827d3bad431d9d38e350c27" },
                { "af", "4967f985bb4b175a59c1ee5a51ee603663e4d50e2d86f1e60caf2981d30cc3866e27d28eea39ddcde75f7171813cc64c5a52f55585df58e91309f134cadd3401" },
                { "an", "022fb306012bf8bc5c38c6567f2d4c2b12b02e2b9f22223df8e3f4ce0fab0865d1da498d490443d6c1c647ac7d840cc6c3a0e384a58b8d2739abf59e9a3f9a2e" },
                { "ar", "94f7df7ee7f18120daf0cb281b73bd142b7e0460dbbfb39800e6d1692206a85ac28719b1b3e05eefe4dc2974c5811e424cb674c68be0e81339e58c3773eec7f7" },
                { "ast", "2f17ecfcdd36a07607e43f02aff3c2ee0bbed95e1191f1e1772d55ee203123bafadb645ce1088e103059494e7f770cfbd4776a8fd95df8c2c28fe9e61fd00f4e" },
                { "az", "bfdce12ee13d73bba8db38d483c4168f47434c0f52374b280b2fa5bda8463d710ac861bc4b9534b0697622ad74061e3a9b3b1a2cd9fde7cfe65bc0fd825c970a" },
                { "be", "91826dea1b4770232fe42610546db9f8c922548b1c70de843e53f427dab9e151dd3307d05376ce84fe065578d7ca978dd6791ca0d1017481d3cae7b474280427" },
                { "bg", "830ad58e43ee24e70dce7041dd533d4911864b0576fa935a06d24f13ddaef01598876546e9c0a051695d6ee21549915b3e32182c34f1072c9d4072c836278604" },
                { "bn", "61911831d4a7989d354efebad2d60651b37d59d13e5578dbbb80c2223f809ac982cdccdae633c8dea70e7a5f5d321f9b09258d37ebfd970fd7530098017f1045" },
                { "br", "c026010158f9da7615b25e1f7a947613da29ed1ff20b31522cfe060689f8c7c01714c354f486c79fccbe0d6edd0b60f703aca49a4f0ad66399f1314ec4a810e4" },
                { "bs", "7b595ab5c479ded5facb764c1105bdfc90566a64f90e48cac9442d266008fdcd51e29304ea0f11c709018e2bee47ce6aabc7f5606b96d75cf67d9bdcabfe3112" },
                { "ca", "21835257655e2fdece54821e3a00a3be6c1dd1624e68844324e6fba0cc023eca0531697eb432e72d25e2b788430762ab245b27d5db5c3033b6f6381f8b8bf888" },
                { "cak", "c2798879562ff28823c08e8fc924225286c364f4f3e20f1d5e3a00a023d624ee666ace0cd536d1b4451c4359684a7c469e6d7ceb7254d13bc6d162137c382742" },
                { "cs", "4e02232257cc6679c2e9b70d97120b40046459a00f926675316957ee228585dcee76467d9520a63e8daea1fdbec4b1db835ced861d3d519c412c9630c0a9643a" },
                { "cy", "97fc95c491b43b7a778f1d2c98fdc09561a813eebf547bfed7134900775a11c828f4090349ea49df742458589a4e9d7fc637b3e740154074dad36947c30cc1ff" },
                { "da", "ca7b2fbe96372a9e94ccd4ff39321c6237fb4d9f442642ed56a8187b04361a4dc93a4ce399567384d4d7ec9ca11e460b4a5e5b69f7a681fa796f2c9f242e5acd" },
                { "de", "7bbfb866da8dd6a87f9a93a06bb5f2477097c3c7d3ea367b5e43885a164482d5e328743bd8c00e33813108ab31495ad01ba614f6ac23157d9ef7453b0582d03b" },
                { "dsb", "cd054e00afe7d5990e4a4181d571efce97b2c8094462ed8b78c59606b971b2fe57b2e0fc017c3af9854d3ce4cc92a003fd272887936dfe8f63a2f158d58732f5" },
                { "el", "f8c3430265b73e54f40b21e8a9f9ac8cf8c3e4383f5c54bf48dadfa3f93dfb87297059f79db61802b833b8593954e7fcb000b1ab6f0bce3342609419800d938d" },
                { "en-CA", "6d980d91fcb153bcb5f92077edc5586cf0f0924beba8827bd04fbe83c45d8e9a990bc1a719b31f7f2fd683690d5d3ffc02913cc76eee6c2a8f160ce930fddbde" },
                { "en-GB", "f95fef45969f41f94345d1a690d3017f05370beeb5b17eee7e6931cab96998d4abbc7e5996c92ec5292a7cf2e5512eb21313463dcd6c0facd70073abd01c68c1" },
                { "en-US", "8f75b6a1474be10f7fe048980155286b146dec92502288bd6109c39c670a94454b36885143aa564c8af3fddb70060ff975f9ce058ff6b30f7b18d6befc860b0b" },
                { "eo", "e26d37f5eb0526ae89abcb593846186a92a75db885018935935305201cbed231e5e714a9d64313d03cc74d1ca373c0abcd1b92abbef6239c10dee08e2fd07f40" },
                { "es-AR", "5e0fc69d6ce22529eb9acce067040abb1ad00c161f6c5be309e8b0575d475a0daeb9749da7edabee8abd4fc54d2bbc1c9234fc0b9fe9c40e4cea4a986dbd99ef" },
                { "es-CL", "4e4d99063f2e16e7eacead7afa400a0338a39e8874aca133854c7362b2af89f7921755b8fde4875a565fb9e861c187446be80e97339bd63ad1aa06a1bb8e1b6b" },
                { "es-ES", "5acbbe8ad4ecf8b31385ff3f13292ebcb1a96b5d2462aa0ac3c2a8894c993a51c94d1afe2608ce47ecf197534d7a4c1b43ad4cb4eb8ee303b0f96c29facc21d0" },
                { "es-MX", "ce0887cc43e251be45bd83a948fe86c748f013ae81bf830b8b7a1fd53ae8f3044e179fe3640c53fd4d2602b64e6aa55c10fc3e2e08ab6ec63f561df8b32a3a3c" },
                { "et", "20ea3004362a06b383195944af2c16b96c5acda1d0f40676181324ae22d3dfcd2af812a9611dcae8d497c9b8353152fb10e7e22a6ab2403bc018f369887f0a0f" },
                { "eu", "383aff3d1691030d225b2d1b6b1581f4f3ccffd28d313621dbb6b33f0e253a562fa872d90bfcd121e6a6afbd0442805a7b0d7a75d868e32efaf34a021523819c" },
                { "fa", "a0a5d3a205697d3967a6a6af48e6629cf3fbeb40a0631e433391cff783914ce78fee19c6fe8cc54d5f16974c5b97117e0886818b24a26bb0253b0619ee37740c" },
                { "ff", "e7c1f536496f8fcc9de192d75129e1bd2596cef82e190a1c915354f3172723a64382022dc882a009884b6d8a2c5eeb9ab3178a1a20cbe37d4673e0b08cdfc8f0" },
                { "fi", "b5a8f290fb41331d7ce917c52555f55eb8e6ca514711b16feb79ae96eaf148e032a472a6625b46478d27c480c044cb5e702d0f312da3197ca26f9756c08c2b0f" },
                { "fr", "cc51f351ee27e0f9babef9e91401ad01a9ead94c9bc0f5109864940d2d6d631d1e75380c397b66b1e07106a377d73d28c9b0a020655cd4db88c86d2e045324f1" },
                { "fur", "d018f1e3da9272caa781e38b110083d09fb6a533d30a7ac0a2bdc7e78999cf8c3393fbfc6b16ccce7f907e85e5d0d02419b0895c2899dac943f56046d24d8b9f" },
                { "fy-NL", "ba596097c8e5f448bbc32092461a1adba27c11718191c957654e44a2d0beded7a6c30666a6a5fe9ae81a5ae852b3545e02b6723adf9f81ecf1e4880ab9070c7e" },
                { "ga-IE", "ed94810674c33afed3535922d9d02bd8755f7c46e5ecce2d2d4ef250c4863d6d55829e0b65f5788339b2f9825e7987d6cfb85dc07ea141d14d105334f91a41ef" },
                { "gd", "2d387d4258f1f9d6bf85129fd25121c681f420b210bd9cc2a6743661fd07cd187f7b1facacf0825fe1ecce4a84e95d6920eb5313a2f6e31b3210ed3fa8a470a4" },
                { "gl", "dc2641facb7bc7eb2286f751d7504a57a8371d3d8fc7ab1606719324f1560fa7f1b76a98030cbfc96fa2e22c7f7a409a03e122dcd9a78acf9611e998b4ae8269" },
                { "gn", "ece38a125ac4d84b3353411f667d7ddc0c968998204fa9e497a36bfff05bb7765c89ac55f0e705f54917e457a3a69712dd78bf8cbc0e171fd000bc1aac7ed313" },
                { "gu-IN", "adba25838b1f12317874ca6f3d0447289c60e60285088f61436ec25c0ec72a22a06301e00fef1db8367305901f19e3bfa7174d9aca5ebf1d8af18b691b61c9db" },
                { "he", "821e973994fc05041ad8db8b719cedab3b68d20b1433dc49ca33bf850ac2e4b8e24a7ea7c01fc99989b1b79bb5df20580b7e5fad4b8681a7987b49879d3d57e7" },
                { "hi-IN", "b2ed7c0b777829492b7f63256ecec169247f5b9628fbff6d29170c75b3f78fd18d69aa012298119fdf5ca73c008aecce39777de3f005c485f74023ee39723164" },
                { "hr", "bdd036609931ebb3d0941207a9532ef94bb8af190a963c235d3e83ab9cf3762ff0681a41e4205575c228d5f7862fd2c425a8263b7b0f5f1c71422c449f3f2748" },
                { "hsb", "6add3232868a0a5cac26a12d97d02d5a0cdc31ecdb1adffa0446f4339f9c67001a1b4c969f3872a8d65cb52a4a77cb3a2dec9b42e81d8ff9b8c369363206b484" },
                { "hu", "7e7fab7a20e6e8d3556ef49b611869ac8be098a096bb73b00bcabb0c35a87e38f17dc57bf1cb67ed84657e0f922daae0a42de603c9af80558816796155fb4a08" },
                { "hy-AM", "07452b93972ca6c18e314c9815d0a56c107732f7d83f772c8e3b7b09a565e47568bd5ba77a0316e742e46f729ae131439b6b0f6a15b56c8186e515b2144467f8" },
                { "ia", "3283a9c70655b815a294f7af1acf00dfe3269d1c543ed17b1d9dc5afd9d9c80830261a5d5231126249e44f8674f79d7cb4432c30455308d6ff998f352e3c59f2" },
                { "id", "1b5aec8549a1f9b65b16e4132858f833b19c2a82f017b0d399f87dc0660add1349cd90091e811f20e63505e2156cbd21f962e181e16b902dbc16eca064dcba97" },
                { "is", "30bda115f0362a67da0c37b858de33823c55b089d531df3dfbc750ffcd3eaafb5bace3dc6feba7062ccab543752ec4a32a379967f5b9479fd3e0e81953767b96" },
                { "it", "252b9e2405e367382de02a1223816d50bc6e36c7fa851929c212b7b3fd78defd4485f45ebcdc02960a29ee4043e8620a3de7e5e4c511b4d06cd7f6c996195ee8" },
                { "ja", "c56a259f9fe9a643e1af5da530a0ed6cbb64b5c1e25de599d8f810d2ff7a7580d147192bed71089e95561e26a86b3d8c09aba0ae18bdffea58af14e8426a341e" },
                { "ka", "052b4c8a0e55408e31cb5769ecc0e747ba17e074d0d8e998abe67ad011a9b8776ead85c3af46550fc116d0d6cad7b5e86f02c7ef1659b36f839b961e8d275888" },
                { "kab", "a7ddffe164879202a1b0ab49c8509c66bb7232b574a2a93065872b36fa95c80ee46b23a9e1e65df6e325638bc30e47e9b016e7b78bf1c88c3c95bea077eaecf8" },
                { "kk", "99aba14e5235f073d503e60feddd301b50fe2ed1a99dd485c2a122bd90a7b32d3f2fa3594605f54aa44e67e15e0f557cd2ff879f55caf89f9b1dadff79da932e" },
                { "km", "7b575235f21fe50a5b192c6a20ec1296ecf5a46f35d3fcb3fbc6f097bf73802c82b1dfea6c79d37272cf953d11c049fba9060d01cae43f09964c7a876fe9f104" },
                { "kn", "9a2f5d7348713231d3defb0bdf9f80c69e6f18da55976b956207e5b607cb92f2135054518f3a77058432b8532026259867f16244f0f6c36864f817c527b00dd8" },
                { "ko", "fcc5c479224b65b767ad56a28345c6c01bf4a94a97a9932650508dcc01ae02dd6d8db4a311901c5bb9c2b07d19f36459508dd2c00b1d13ee29fc10668d1f676b" },
                { "lij", "be62900f9bbcf830f1418f737db159daf3daed186feb5c79a56d3ad939d727c6fd461d7ed45fc377feabfc43c79ca3f4062bf86f40eb48fc83fb75d4d630304f" },
                { "lt", "824fd7851a144938afe80ef69827d689693402cea458e07dec7b4b70ba33655316ced2c0146e78a4241541b31bea8f03dc7e8cfcb8e4928f0f724fee839edd8c" },
                { "lv", "dd9b1650af2ba95bdee807013a3aecde527ad99342e8b7422a898c712253e1702ae7f0f1f47cdab854138c13170c6e11e0dbbef30063ffe8ac6a3c2eef5abb11" },
                { "mk", "799a1a2c2fc1d16cc2cfd9303ddb617faccbbac27bbbf859f014b1c227bc0503ea700301e43b94b4038b1f3b8fc2ff9157b49e8abd0d4e4a7aff5dee0c808a05" },
                { "mr", "a503fea815d9d18cbd7a4ebfd78f4055f8c1d1d80a26302890a88eab2f676fff1ed0258d444c4c2e2a80217aa8f9d22978ae74fd591d61c9d12054bb90e12af3" },
                { "ms", "375a2c1909bf6dbb8cefacfc1f081b54a2815bd4835048f100a166fdc06cf5da395c68463b64471f8557b57438b182ac6cf58467b9616f717adabb039d034cff" },
                { "my", "68283320046575d3b5f07a0cca7955fd61a895f34df2e459744ee6c10de0c97b6e9c65ec09460d5b1a14dd895d4470ea5b055af479e43987919b9fb082e69ea9" },
                { "nb-NO", "1b45a05afac0ace5932aa1666a7ba72579a08408ab4b53f76cf9864b804d50b97f0b1aa1b4c8e57da57c702b5bd778bdb9e7ebce88ac23ad35bad83c2298f323" },
                { "ne-NP", "bc52664997de2eccfa9c7cd59f86e908230eb9e2cf4071dffc9ec5fdadd4803c1c65e2ba001ba2fe62c18a7cbc0d366b79b3df4719d259aa18cdbc6d284973ae" },
                { "nl", "0e19711bdc5370c975a10ca94960278947aff4d24c04910b2c573e339a315728736ba615759684ba0bd4ab6dacb3e6fd8315d731d9315ecd776d4dbfbe563165" },
                { "nn-NO", "c93bfa1ad38474ca75e0bf042304bd8bef87546ffe139161b861706dfe8f5e74c8fd642531a8df4fdabc576b4d180732867a2b6a048df3fd749119f88648e8e4" },
                { "oc", "8df4ca75371f70e5a6e0543077276565289d48fcc5f267decec4144a3ec8b330983c11289ba0199d49569dae5de784ebfb1a6afe2b5b3c7df7040b2a8f6c1139" },
                { "pa-IN", "ca9c7b1f0bc8cf7152955cfdd33fa2d2ad2c34168482eecba4e20a5cf5c499966b36f3b96b607736624c0de4de18994817a13e86bd4b1d726e92e2cd21073c4b" },
                { "pl", "3e759951f3d4320e9a0833926391f0b203c3188405686a10044b348cdd289f29684ec063a4de2f33f72571544a7991f0ed7dc820cc0a3fb9548cbd684ddafbec" },
                { "pt-BR", "f6802b374e2efe929ad3f8e35e45dc380ddcbc7f49027540212e4593564daa00dd1f7d635b0d4fa25bb90ae9a583f5e45656f7c5617284c059c7e455a9fa7d3a" },
                { "pt-PT", "246f1ebb1394f0c1fdfc62ed692c5634e2736be76ac4b63ed05c5edf64e398c57040dda57794acb52dc0b9fa1875d2dead09036b4f52227cdeebbbea8e162a26" },
                { "rm", "91f1fdb394a9d8ff4d3dc1e7ae07d53fcd06ebfc73ca7dc805e6498739fb6c9a7a40fd7908ef3a9038576573313e05a8d9258b0ef911771effbf4a95eb4343e6" },
                { "ro", "8ad06c3488062370c0b2b6dd76a3500cc79db6c73808016e6fc3880bcc41ef4d42d2cd7a3fc8f6a7e6c88caca7f62c464626ad59dbab809cd7823eda42add5cc" },
                { "ru", "5676637aaa2060c9759e35c337c4eec5cd251f930ef2159e0ef4772070d6d6a5f2a14a9ef634799ed7d5f2ea1bdc31dbeab62d5adba3afd0815cced942ca53bf" },
                { "sat", "04faee89567bdf4ca7a92e267830d0db92b05b1edcff4a5d508ce19115e28560539f8d039a35c74f08769970c1905fe70f2324ca24e81ba787b90b18226101f5" },
                { "sc", "d6e1eca6558df2a060028c315336e315abc0ded9a0f49ce74cfa50c0ab961b0f518568202587e1e3ae3ce496ded1ba14b3bba29ce5bd99d057341da7f6cc7489" },
                { "sco", "46693bc2dfee755718d672d9a48c83a608be3ee5b2111ae12ddf75c18e0aa1ba3a1a4b63f6b2048f6c0228b1b52fb1deae6351606f0c1c1b56e296b22f1d2156" },
                { "si", "4e9cecd35fd8a54943174d3768e9efa16a74a79756573cd01b8266abb57a094cbc48b78f3e0062d00991992b7a47dd7698e3cf0fc63b0ce05c2ef2fa48e7e27f" },
                { "sk", "421087c358acc93ce33ac3f978be10c858ad99451bec573141c22f6b37c08c946bbfb7eca1e09cd1ff291059ac1bea22dd1cbc35844404cebac178ad5617f19c" },
                { "skr", "5538160eccea666fe92d571e0b4a5e1f08864233d3eedf39057088d587bf950c38c97572313c11573a5ac5e29e3adef96d9b2961aa83979cbb19e627cdc16d44" },
                { "sl", "0854da24ca36bf38538a9b6ed2fa3dd0ccae0ac94df3b8d3db4f044387b47b29132ecd7ad9463d1a2179e8109dd22fc5fa8169d89a2af8deae2fa97760c8538f" },
                { "son", "f59cbbfc32fac0eefddcfcec2d612478a0a4843446f4b2711a4388caa7887218ad868323e196b4363efb84909073ea42cd7cda588a8b76031ea70bd4ebb75cae" },
                { "sq", "d50c222eca7ed172275a23fbfb5fc8879ec62c88626e1bad0d476f7419b6497dadd983bfe466afd61f53c869262ef209b6fe85addd8ea2864155f9b1aa1581fb" },
                { "sr", "72d92fd80e7a2be5c284c62bdeabf1d723fbc1232732b1af12c6dd6b2bc216ff22a424b6f5de20ec3406348be60c9905e605c21b9f1d02d583159edde31f289a" },
                { "sv-SE", "0d006bf84bf7773c54489c33851a9d88d69e05a60f4753fe8a5b113d6143d3e247bc3e02f66f2f2c7fe703d56a1eb868581daff0092d7b3ed7a1926c208b4a86" },
                { "szl", "56c3d821b71dfc09b1a148741805542bcf6dc1dd89507535cb157469a989e53b7048c349470d0c0539bf3e103ca4e1fa03bc395aae1f1585decd7e26e0cb6138" },
                { "ta", "621a1590245b11f93d29ae0e6f1cc708195e792c8dd4cf651a39fb9be1b1779119f898d4932d99d8a1ab3c09ec52b8bb376e32be2bd66b3fa16c7f9c88f898b2" },
                { "te", "76fa98383f53f83f5d873289607d07ad080dadc5de8a8946e25259a24809c131346375734e8fcb60bf0a9bcac34b8d03fa1e56f5be4a05977d1bef32fbab0bab" },
                { "tg", "7e5f96de97f73b3d587c7cee02d67df485f93242daf9b4a40042fee1aa57836ece9309495867aff6d7898f9238cc1c8fbc17c0e995adf3388deb7d5d06e515b6" },
                { "th", "cb358b99478e87a7d314b9f7ec1318767f928c18a592f1ae4e83951d46b39bc9eda8a58ea46ef61f8b022a62f6a3ba3df374a8e8713daf6a8d5d99d85999c077" },
                { "tl", "2303343e457cc997b437877221ce38fad69d8d9e5c383bde087ed286833238bc846a1fe76f3efc0846a3920dcec17165530712c3489494bf3025af88e293c068" },
                { "tr", "a32f0c9d7febc3fc6fdaefdba7685d542f014f6ad1e05698954071ad637a433690c2a71c3b0320fbaf2e679a881b43db18e9fed5809c3be42b343a7ccaea67ef" },
                { "trs", "f013f980757d11fa39b19015d41b5e1e1013c7743af149d8ee516615e0cdac4352c5e7a981c2e7c5c94fefed61480eae208a73190ea614dc99c47015e37c87a1" },
                { "uk", "effce3b5d201c59e9539c717c7f8d91a6d1628c773729a3f20bc27c3a66f42935154c19390b2d3d81bf38760a6bda85f18781990c2ae243570cd17a137ee8a46" },
                { "ur", "c122823ef0cdec7f05612267a348e5391e26b7fa0bbc1689d1da1c0c80503b31628cad9f3ac2140cad28bd3e345883df9e1a4c6c603eb7bb6d87e383c0acf047" },
                { "uz", "b456467bdfd0208c942126d8da947a00bdf55ac7b4b3b1dad2028059ff9fd14903b4eef81ca67a1f3503247c620b3b8403eb0f994a35cf00ffc21e6c92cb0f46" },
                { "vi", "575a1b93e75fa519ff5b2381f03ed8def4fc44e52ca5c69eddb1ed570fa7e76472d524a350e7324beb018a22795df123bfa046db8338bfc162ef97ade2742f71" },
                { "xh", "219af369ba832f5ced840c318383741180c313de52170ece6e3c81147afb7152f46c3ac545a0da4ccb8ff414fc61a14b43e3b7bb427126b7103c968d3e398ce2" },
                { "zh-CN", "3c9f119fac761b71f768ed1ea27dc4c2e61a56dfc905c912079740d5dedc3bd043cf57656db7ce2460d4f427945be3c580d46fa17f7e6e997088dea401f3e518" },
                { "zh-TW", "b9bcedad573b6d397b16f162789977d39ad53a0eb8c74d7592ec50ebe2241848d6948a6fd39df240c59f461399568aa9fe4f93932f01ec3c455c96a1c182389d" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/141.0.2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "eb6659f8820637d51323a3ef7df61f3e3110fdefbeaa89415962d2cd6169253d2e0c3c6f8399cf235538f32abc30665c13144c5a5571f2767b3f2fea336d635b" },
                { "af", "a62585ad3fe836aaeb1efc32b242df2f1309078984c1ca6413ff762a5d31cb74491b787daed5f98073ca821332027e067f1c0e15511715430e2185174c6afc1b" },
                { "an", "8592e0d3086c9f277f67904baa10439d74bd51cb016da054456d1e737dc180b04fce47e5f9d48294512ae74eb2c78aa2a1eb9ef04a0859335b302fcf8226a695" },
                { "ar", "315c5a4e33ef62b7b0eec50ac84ade36602ee4ba7c7b73a2c03cb6f0a7c1747a9fa6fad6ae02dbe4094b85d64ae767c5c0b5c1ac43c025ba22e260c6ecfcfb26" },
                { "ast", "0dae400e167081658b83a80f96fef8849869f09fb6462c19d7ef6515253dfab04e2f1bcdae39cb2f5b3ab6ca941ebe53f97c9627e772d9b45e519bb831e0aff2" },
                { "az", "f7ab0652b9f96482022a12a8a40212355f218c004aef65132531858d1b3036f2f3d6e7f0b25fd57f74373ccc61c0a0d051d476d1152143ae12b8b0a4afe26f0d" },
                { "be", "f7109d1edea649b91d1d53e7c097b8a6ada5d625e1348d5da21973f79503b92f30021f8ffa3f2d9fa7239aaa5aa8928330fbdd5516f1523a73625442ef572fd8" },
                { "bg", "1f9315e79d5c4bad575e072236ee4f0ef8f1ac2707667d6e70e540b3be0de3c7ab03152bcf8c34bccf5aaf571d9ee36969937a1485ff91b20f0b12d1ab94a668" },
                { "bn", "58cae934b8df3aa320d7709b55d3d915474c9cdf5d7593244a6c0f95ba4cd0ce6467fb943749e3789f585be1599e0104be6cde8d67dfc119c3cbbd41d9a539fd" },
                { "br", "90675df1e9bdddd75e56ac81b82b4d447826d083a6c85473562ecffd61dbf3cab8f8f6994e45e540d1de5a75afbaf3f99ed4bf0e1198a18d2dce34463d6b1248" },
                { "bs", "c4b48079a52d51c1b0003889d409946a1ef614a8ad9f73754c199faa961e081253ac1c0e62c38fa73ac69bf1c1809cff0adcf73102288eefc86cb7e787e104f2" },
                { "ca", "c3cb5db7e0224d56ccacec1abdf673d97f04aeb9ff3d2968e65fe88d524210580fb1ea64025a8fa595f05bb97912a7533002fe47d3f913aaacdfd14a4fb5290e" },
                { "cak", "766054439eb94e28207f3a396011f22ca0d2ca6397c7ce05261babf16528292330d2b46f8733d031bad66bdacd0d2e2949abe3246e85b4b5e0cba0380f0973c8" },
                { "cs", "885d3b5dbafce9578b6afa192caf65a6198d027131b6b2fd482c4521581d314cb903aad5ec537dfa2a426178fd5c979eb731080e4f26b98ef6ea5eb4559a09fc" },
                { "cy", "3691037974654812f06753a5680700060dc4fdaca68ab87dd37e331a595d4218b69e1abc13ee536fdc8f5d4368d1e3c11508e2700022d6d3e212cc4e6ce1d37f" },
                { "da", "6687e34da53ae478f352884e3ea982e54b88dfdd102fddadcad0ef1fffdd71c4b28549c596c93c124da0a8bc0c2519ca177937684e3e25d5ec9c797a63f33ea1" },
                { "de", "82d243548639db66b55c49bd41f6210491afc05c1a67232e2aaa66cd48d71eaaabf2c8b7edfa85f3463cd1922d8693048ed8d76ccf3ff01fb576d014c1e4d37a" },
                { "dsb", "1923485a24499f87ae393a30e8078114ddd10438a2ef645a865180b3ae65242fbc766bf31d302a6dd7b13c531c3a59cf221a39953220ffa146356418a039851f" },
                { "el", "f6d8dbb1fa4bc673b2db4488e1cbc2543abbd317d7f9c3736fcd2fe226197eed9711d1b06df03fa6659742042679eac4428d5dfb9816c8f3fe883e9d80661860" },
                { "en-CA", "d3bd0d436376fdd715940bcfe8c46d230a21a8c2b1b4ee6cb002ba173136238a02d8ddc66b9d3c30845c21b46b2e5642f1f1ea17418f901052be307b2d785dc0" },
                { "en-GB", "cfcec4c5e10a7b34df6397a1a106ed5722f7a4f2ebc16686dcfbdcc7b27dce62a41a8e97913e00565d075f35365e8fbe1c3fec7ec702880e762f7575a553f5a5" },
                { "en-US", "3d79a1aae098d892f191b888b9dd70be016da91fd940ba20b1889b7ea0d09b513a1602114f272acc05d3f0568c695bc570abebb3b5effe1ae04ee3e3b2d02b0c" },
                { "eo", "1fbc5fe94b438aee648d4b537aacd3581d0f782bf818d43cf2f745ad343d1895348cb282299492e5bb1a6d415abeec17ba0dae55a38b957d5f5b7099d9e67b47" },
                { "es-AR", "008615651dab5ad35281d6498fefb340cee5dfe53d0e656ba3b195344698352edfc07ee5de70095a2564a46ef0e1d809dc94586e7018b5b6a35ee70b902b18af" },
                { "es-CL", "318d224f14b76079c7c58731b6ad200bb982b27129e0b6d0181d1294e31aa62527df881c942051436b593d7395cc3e7cb4381a0b9044cf56970c39a99a4c22ae" },
                { "es-ES", "1f6fcf184835df1fec0daf50fdec61d23a5182671fd8f7d40c0bed61c0b18cf2ac448038f5bf4114645bbaf71f9307c5c9d53714b5ebf729665e2020502715e0" },
                { "es-MX", "9953da907b07cafb9040c1576d13ffc29859ceedc2b14d4cb062c124041e46e321047f5697aebb7afe1e94ab47b99259284042256e64e0ef819269ebde1b82c4" },
                { "et", "67685386026f0e22964b91c7ad9bac83cb6dc6ccd9c57b83aa4a40e0d43f9c8cb49cf1cd073c5aca0b03ebd63d570fd52b67d11c7fc1a1d41320038dd30bfad6" },
                { "eu", "62ae2bbacad751f35113e0c6143d86a9c658f7cde6d36afcca381564e048b18e6f856ae47b96b6b4fca227d1bdaf724273ea76351840323ad9f783f601a2c793" },
                { "fa", "6ec0b7be3ef124f02cf02e2b471534b5e864a2f80dabb1e2e9db6b06af96836f40d74e192ce1fcd11f986df6a4fc12773e288cecc6c01a366df3586bb829b756" },
                { "ff", "7cc33474e173c306371eda1fcf5391ae1dfec93f054fe38a0532144dc4ce9731c69191c731372fcbdc45afb0589c66e6d6f738cf4066d4a4d6be548c11fde875" },
                { "fi", "0a92511049eb2346382c82c0a7399a1ecf1c0596fb6cbcd12386b53eeae3f1cda9bc1c0e7094aedb00b76a61e2ef72349dccba592c5b52eed643880fc8e7bfb2" },
                { "fr", "5421d2d9230dda4057203ad94a1ea000f1f134a5e658e341c878bc808afada3b23fefe6715b5ad0db415cffc9b0845a807942fc256f9feb2d02111aba11f3888" },
                { "fur", "47699420ed363305eadd2a7268b90e5dfd9b1855e6959d202e6a6af4a9fab188661147f14cafb34017a32e77f62a731159968c2ee6cad2107abfeaac247542c9" },
                { "fy-NL", "767240033e3f5c1b626e1031b44a97015dd45f3db20006dbc88da14108ccb2a70a71d1243567c021e9e420070e5d60ba5edb838bb584752c1eeb498e21b35c5a" },
                { "ga-IE", "8f8c444cd34518e7e5818724d52799aae3030bdd6d85505dde33b60a8a8617ecbbe2618b7dcb532e7ac30f6c22cb515b7e48716eb649e0f893023e3799cfe17c" },
                { "gd", "02b8c2a6a19da8821aedb5eccd1ad04a439f88137f1cfd67b095b6fd4b81229027c572004da7da24ea590fa60b4cd7f14576ed1b7487720b48eed545ce9f7cd8" },
                { "gl", "56261d328ec08e35f7dee4ab8440671bf54a86e392477128d0a1840c25e274db10433225b9d5fca6dd1f663c27f7b8e14218067365f2355ec1a7d2e054284ac2" },
                { "gn", "4cb9be61da1b15f0a72f15ab8ebd727231b97a9320b3d6e1a4c829c5276eba0a799badb84d80a9b47b2af5235397f1dcedf5ade7839f2af3f910a92c00bbd9f8" },
                { "gu-IN", "430911858cf6b17c9f9c6edc99047afbe3cb76a68bbb569651c9a9a09d09870e897796fa73da90b9a131c7ab1182c4b5e07591311337dd25bd54601acb967948" },
                { "he", "262e2f522f7aa04d439232876f932f6bf0e3a319410e7d8e420324dd417b613e3cf020b61869ede29012fb03aead4959e660e1aa2f1105f8a80e1a4d8d1bc21a" },
                { "hi-IN", "58c15107ba8908f8c9777dd3bd19a274d8ffb78eb21f54827d9f2144bb84c1c933813742f592eed2db9edb7afb86b7fff858acd344d343827d39da4c75470ea5" },
                { "hr", "ac4c34b9ad1d3a2fac13addbc200364476b868096dafc69e48ee274e6be7859b9ed6fb96257f7102458a6913d66c25ec316972f38a26bc0c75458fff8a22c6f9" },
                { "hsb", "6814ec173c9649a862b7e06a62b70c74a72f8876efce1032855c2ef0ecb33e8a7f124f9c02f5750fe32736e5a4b7edd05ae291391bd7e4ba955c87e7953b9a4d" },
                { "hu", "e1e7ab366d61d0d46308b1edd66a992f3be917077140305207a70d85b6e4567243054ade148cf3738c0bfbc2561aecbfb572965e5a2209432175e2fd5676cf73" },
                { "hy-AM", "6cda6939bf4f5b17eed377163eaeace0f92894521ff6e096dd133b5f15aa395a653e57721aba5cccc777c031b8ca25c3c84191bff48de5e4c1c49342cf4a3a2b" },
                { "ia", "2a12f0dc5e88dd48b4c8705546c9fe28e13e01271089f7c90f4edd7acb1a7a131989f4455de1f34eb61e97348bf2c4c947a9a00e5a840b01f798d71576b9007a" },
                { "id", "be538acfa51171bd4c64a031816fae2d060f9891a485aea3039c5f3aec02215dc14aac747504edd8668d62d5c22b241d6caa0b01c94852cf7e0dc7470864195c" },
                { "is", "00fc68c96dc5f694dfd54e994e22b168f5faba3b957e1b4b44e4a5b619e2ef3946f5da234db0927bde5eb17a1462dba69a1af4c9177606bf25a164e03d994b0b" },
                { "it", "0a9f8eadf1e9ca6a1b9f3bfe89c33823f42e17bffb7a9e2308c9345a43cda4b79675309c4e97bc449c8375520f2fd56ccf90854328e501e4105ebd84e0d8579f" },
                { "ja", "75f1b28997f91ad029ee82c597003f1e0ccbf1cb9830697b1922e29376ec05437b3daada528f985cc3f874565b03a2e5a0fb10642234f37f92b8431048f62272" },
                { "ka", "9b1b0ea549baa230647bd1982cbbf84a683d2faf3db8fa87b8bb1b5cd2ed932caf8cc9294aafac24d8d088e8caae07423abe277603422e990336ca3be64e1086" },
                { "kab", "421ef222f8d5e4dd97fd221b8534eb1481e3cb730d5cfffae6d11c93913adbd03229aff1409c8cd93742f71665948df743d461e309d73f9962645e8d7eb2888b" },
                { "kk", "5ed1b4ea31ce4ee40b05aa436c20bd72c88e01375e8f101ed04251f2ab6e5ebf70fe7b3f46879f37f5ca1349c34db663889b239bbf4350907ba78733a263c766" },
                { "km", "8ca9cedb9a36dfe103e608eb448b40844f421e1fbbf39612ee9884a4a7f192cc6f124180c0eedbbcd58bde469757ead040b2c9e258a89a847b0a5ccd093a6990" },
                { "kn", "3f33d5b9ca851ba17b9d64c4f6dd1a55d808d23c8d7f14e014c28171741b12c526805aad237b35fb3fc34ce4cbe7be3d6d159e6cc7b1f94b7224295a82173794" },
                { "ko", "3a8fd793c85672d3e3493831e3c913037a26c767a391d6f67f69894f4b93abed3499e5f2086b690f7ee6fed61c9595157029011ab9d32c9fc6a41fa7a0008c42" },
                { "lij", "784e90f1641d2100bfdb920c611c17a279ecef988942c881a6e039c1c402c249688b2a30530bb5057d8035a99b9e4ef21c21580622d0c167ee0d32abf92b0d6a" },
                { "lt", "79487caa13c66f3d59ea9c2f8a325249c299863b3336fccf2cec7925f0fbffe8eb1d16e13623887059826d14ac2fb272595d9c0a10876c01b1ae7f6eb11bafb2" },
                { "lv", "f2f0c91a2940deb0460fc170fae74f87e8f699f37099dac32d265f0b19937046a3fe0fe2ab26f83f267558e4e4eb7f2eea8414de8c9092d7e0ca2cc73df8b898" },
                { "mk", "1ae7d9f36c8c008c90f81c198c952e1a4d14c7af64649342b635ed381570f1b8a5a54ca84ae82c6360b88c34c18ccbe8ff4dd41ce9532dbbe5338524e4451d78" },
                { "mr", "7132a9d36726f6adf36980501873201d6d4ab00959ec0581e6738fcd55b05330f445bacbf5505a1aff0d45ebebdcad2638f7a02adf37dd2c98b5b64c97488d26" },
                { "ms", "3542f0b9b51e9f18d8e4a806a37ef53fa19f44b3528473f4f69db86eaa3f10cccb1a9eaa93f3d558131d4ec21b32544d48fddaacf0c6fce09904fc30be18c280" },
                { "my", "7795bb77f8901b68931f2d580225919b38a5332657999ece2fa8d95ec2be879b6dfb417be078165b15ea93d5b744d9ae8095df762aa34e37d56c232b6e619ff3" },
                { "nb-NO", "7d65558c980a81503aecbd28955ebfa7dcf5f0e6ce2efcd8c73b9b6f76995935bd38be9a414b5c3a34e1b9ec993082e8d22d01462093d5fbc6f38d5b0c1065a8" },
                { "ne-NP", "c6f086a5505780c5232ca9cf290517bbb4deb0f422e6b5da64c5530dff90effa084edf64b4b71eebc3d282a273413a23972f47f39ca0a308a946a34390bdee3b" },
                { "nl", "82a09adc2efc812449fa6b35de9b21995d5efe865e6f3446758a946a5c766990ff7acd1ec58c85a880b1da6baa6a9cd6cbf1a8d7bcad82c09502efe85f7fd0c8" },
                { "nn-NO", "ca78af41b457c1ae5ecdeda3c5ef457dc13c2b8c2d205988cce2d98aaffb7da4bdfbd9ca7927a0afaaa37baccfed6f7fb20b7a650ed2c8d1e0411def6e7a34ae" },
                { "oc", "87db7d9ec5a0243ac23da7b4de7bd232e11ac638af9e7254a3243dcfd0402992e7c2a7e0cdc8a51abd86112cd4a040d3fb5774ee77e427ce746afc3fe3d57bf1" },
                { "pa-IN", "a8e6b66644ae93506c7f1bfef716233fa1811dbb1ce7bb8f2e17e0e6821e8c452c017342ed006f0672e6b23d4e4c896098574d5522f31e91d3dd5c5a85feaab1" },
                { "pl", "2ff464713532035a750829e4c8aa18a19f3642773bad8b5404c4d71a7c26bde6fd741b7fdfdd9fd579a7faf5c233885967753cd33db0fa61900df757706173b3" },
                { "pt-BR", "e8354541846ac3773510575501eb23ff6a4ad360dc76f7a16acba8239863813d9f42be57a3b9313ad425f30454758ea5028593839495b76d556ce22802cc52b5" },
                { "pt-PT", "637e6a3193e3b0ea57c25dbfa8650f94bf140402b5cd23417a15e6bb23158cff1c21d1c8116345d6c540a730b085da4dc5908b5989f116318104a320f7c95416" },
                { "rm", "4e6e2992e73e359f16994b14fd2e4b15c9f86f8c6c089af55b671da9cd25e98326d4114ed3f422b35280be3c50bccb14133543660387512b9f80c25ceab1418b" },
                { "ro", "487027c179d16561cf57b3eb52fbfd209364afd704b5597aebb856107927c7cd380b7a55412234d0f811b25f24b752041dce9f7c8d42b3f5e8e2c76e58205adc" },
                { "ru", "000fe64e42f097369db024cb4d31c05e8c7a91411355a0c56e2902532178f3a895ae7b83d2d4abc1dd283965551983261c6d404618bde694253f68da7e92d931" },
                { "sat", "e61c3edda1d04e5e2a11bb2d18b77d7036106c5a4b129ab9c091b26995e9aa022264cd39d12d282ccb6ec5dcc0277bb6666436cd9fce356522c00fc90eef7847" },
                { "sc", "68dc4124d91add068d3adccb21cd8d786b07d5332a82ac2f7edc52b4e577eb86bc7eaf758b05048c6ce929872f4995df195347c411726a0a502420ff09b6f601" },
                { "sco", "183a41f1890287f493345f6c8a6fac7b153d46ba8ccf46f65edc9c8eafcfa84842eea79b2f6c245550f6746cae49bcbdcff2adb94c59c3fbb87e322841e14288" },
                { "si", "b506c15a6c5ef301b15eed7eb09a7a5848d3edaf36a664b7e3b8d75542bd66d97f91d6d450e768299cacb9141d0f6177751db035a8a45f6de12e475fa23ce151" },
                { "sk", "0ce352219eeac3256b15a3489e9e402ea3d865650aa125cd481c6a75669a91ad0330863b2e19e41209f6ce4626109af75d5bb7adf063e593ebf636b390a13f41" },
                { "skr", "918b6eda39b88703a6b27c5078b7a37ce398449e99514864cac463d6252d31cac89bad2794669dd1ebf5e9ca2993e18faaa5be3fa3c11ecacd0a68dfe80665d0" },
                { "sl", "fa569e266fb032d7d0d871821b8fee78ab4eec72a504ca3ee30b9b19efaf463e33157358e197c67e64c586aa9eb0258e95024773e1f7b7a0d1c7dc49fa5dd4fc" },
                { "son", "88628f1a6c1c31279c311f783356a23bd43dd8012f732202dc126f70592c5c1656c02e38798d5d92799b5f3f7db9e052b6ab344ad237ec04da0a70b68450478a" },
                { "sq", "7a60732c67a1d3b23c9ff168af0cce1ccfe78682c9db818243eb0fc585b6e08e4913566555c6e75d44d9915cd8c9b962a3316291372631602f514c2854031605" },
                { "sr", "e2e11dba0994c62b77caa9f4a649104d6f02df6f8ba6fcd79245a950afb6919d0a958ba02fab74141c9d08d91df86fa41957e20d8c9eff9b0d3ccbc942e0a42e" },
                { "sv-SE", "740528776b92b9f136d8f11cad27637cf63f2cf487682e60294a8b084be675bd7d0e6919fd338dd2ff567abf7f1b3b8449849de936d1d64fbb14205b15510049" },
                { "szl", "5b089f4e96887d98da9214af906c2233ef0742b6636740fe30c9c6b0e183edbbe4ac7d3c35ebaf4d312124b8ac2be6cb757a7d251321d4bca5f65b2fc18742fd" },
                { "ta", "dd8e83c364ac1a369460f9c03b1172af10f0c7f9d58c9a8a9e55bde85919f86c9e8a31be426d61d72bd0c00802808b4e2d1735336f4b2952ecc890d10ce409fe" },
                { "te", "313145177dae773e3402aff243a6a878c9c10984e06d4c971bbe9181fa806eb600aa165104f8a3f73e4dbccbad84338b73dc825fdbd7277f4898c99cd84c272a" },
                { "tg", "3a8d9850ad3df77903f7d9def95b63cceb23362e5aaab5fd7b90411b987ff4af65b0f51facd605b486645bfcd0cd8442174da9e7f0ea836823b0d40644126e3a" },
                { "th", "20d2a6d7111cf5a9730b88606af1ab3c2d30cec1e0414e17fe596df9f6a7004e7825ee4f9d704a921fce5e30adf6b731c9fd2e0b54ac0b47c962a3749c066e3d" },
                { "tl", "1439a818787d33e2f6b41d923db62bd3f887aae98cf7f75d3cb34113bb2289ba8693b25c38fa0a8ae5bfaad97d65d502e55fd7357f4d34fb21251806db49a61e" },
                { "tr", "b2938717d3ce32226cac20016be8f5bfcc0bed5ef98d34422496ad28fefc878b731ab9abc4b8b10db9205133b0eec37f0426c7637e8124ba831d47cc9017db1c" },
                { "trs", "2999b2e493902d178fafaf323d58300daca594f6dc80f9a71e652f6e7c590f6192b8a0c3b257571c44e108416ba3673b89eaa24163ee592d18ceee8c8f36dbfc" },
                { "uk", "00d556e30d6c66544de01c310c4667406f44991fdc15da9e4ea172770282be027a6b269a2e3baf2fc6b4ed43c273bb3b963f7cf7fb725ac68218ea1ae0c7122e" },
                { "ur", "7c114f836beb53365aef55ac771431bbcfd372d0be7dd4bc45cdfdce9c596b72655d0d0591a3d49f1b1b558c779205070cffa990d154bc7313fdd065efcfa5f2" },
                { "uz", "9fea5d77f0956a7ad5de1b357e1b849771347be9737dde234c0f149def655297310609e0b2cdbb72473d7fe2cc0231e4924b60e2e498f4f16eaa570671dea1e9" },
                { "vi", "18714d38606ac736b34cc2e7e9d855c0646bc1425c57a2c8e7450e9528d800da6bd78ce71baa947976e1f9b9f97db3c4da9805d4479f84c0db79d429fbda5299" },
                { "xh", "ebfb65bc4450dea61e0b385b05f9d55e08b3aeb5306c3148d5f3d206e17eed0f58de9d86eb9708a54338ecf48ce9e42342420df273a780bcff89b81a1069e255" },
                { "zh-CN", "54759488bb6529893bf68f0266a77a1f0542fd395ed30e6f6fed000415d4c701d28ef1c6174361393d2d10c98cedd7ae4df9238a3ae4063afee7e2a9260d69b1" },
                { "zh-TW", "2f80778c5e79414a634bd16bebd804607a44b70617d864e75d2eb3f0461c07e931ef1befda972c09642652c6c84005fe2048ea4ea0f6755f3af7f43038cfbda4" }
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
            const string knownVersion = "141.0.2";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
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
            return ["firefox", "firefox-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-latest&os=win&lang=" + languageCode;
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
                client = null;
                var reVersion = new Regex("[0-9]{2,3}\\.[0-9](\\.[0-9])?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox version: " + ex.Message);
                return null;
            }
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
             * https://ftp.mozilla.org/pub/firefox/releases/51.0.1/SHA512SUMS
             * Common lines look like
             * "02324d3a...9e53  win64/en-GB/Firefox Setup 51.0.1.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Firefox: " + ex.Message);
                return null;
            }

            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
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
            logger.Info("Searching for newer version of Firefox...");
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
                // failure occurred
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
            return [];
        }


        /// <summary>
        /// language code for the Firefox ESR version
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
