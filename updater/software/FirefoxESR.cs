/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023  Dirk Stolle

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
    /// Firefox Extended Support Release
    /// </summary>
    public class FirefoxESR : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxESR class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxESR(string langCode, bool autoGetNewer)
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
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/102.12.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "a20a7d2cc6c22e67b298370675e9e5cd057e605993902dd3f1bd8a3edcfb9e0c351e793bf94d1150394c8daae69e0c1cbca3d2ecc0de8c16d4fbdd77d8ea8f23" },
                { "af", "f41af2970e09a23534c0a53a7c51cec3192cb4dc0c8c7352eef0a69b770a24340ca8a3c12bc1162d8e6a7a348fac8bf94a96a18544e65e42d703d1917e0f0b22" },
                { "an", "f09b65fcf22ff784f10d6d6787f720eee0948c00b77a8b98471f0490dd7c39c2ed08a933c7876faa2d00afd536bfd7fa32fede36db719abe148eb8c3f0cb02c6" },
                { "ar", "4bb89ec9539cd197c7049b6847f76a5d6fac09a8facf6c2fe8aa019fd44530a8d4361d4e883c903abb14676e6c73482cc56cbc538eb0cd25d15a10fafe3300d9" },
                { "ast", "d4673286cd78daf11756fc64115d7fc3c6a809354ba31f25041744649d9967ef0b42c4117e7827a5be0dd2028cda684300087e1bf2a035007bdabc1e7464fe72" },
                { "az", "9feb1ff94aba2b45bd01b54276e16a4e983137133837c169173437207e2e936e50abb5348f29d911d3029cc0771b1da0ffb1fd9cc35cc2119bb8f23342b9c72b" },
                { "be", "75ab095f95d76a84039f56e623ddf47b73bfd90ac079014606419de0fb0523f7fe750e458a435ec2d0de9acc6ed7272238a7879da8e78da667f7c38195677db0" },
                { "bg", "eb24152323bb5eecdacf99a4f19a48e23ac050e016df8e235a4ed5dfef7d18b5b00fa5e267dd37d96e3abc56e6e151361c97c1c9c37a3f02df77540efaee9104" },
                { "bn", "b67c89a77e88192c3642749172593efe426099ec40f8c65a16225b883cca3245071a8c73b734f3f961fe7702fa0042381c536e1630d9258ec0a70985d19829e0" },
                { "br", "43b6fabec1112de9d27f807cc05f4713ab14afeab5ab93f3ebfd49441b1f256e70c74c5d6925a109f3543eaf206db7fb25d671ebf7d138cec32e42b6cce03c1c" },
                { "bs", "689e2bd59e02abed838b8f5e90cb9d0998105b73a38859d5f0c8eaa5ee7b025d5c5f2a4ff5f758684d51f357c6abd8a7ef4d86b5e4436d1c24185356e28c9740" },
                { "ca", "49470bc4ab497f748f4f97cdfee97eb220e8606cebffd6fb5817f1a4272e0eda6fc9c2b26c6b03b5aeb49838b735cfc48d8e937df737f137fdea8b7c2678daa2" },
                { "cak", "5d289b45050630a9932aebb6eeec678aeacd2891b3d6241922a27cf7961b42903f5417ad79d88157941925f57a8815c2b62126f874ea9bb9fde31900d87d48dd" },
                { "cs", "ae0b43e49fbbb6ab637d9373028cba62266de7f1b495bcfea60c2780c20a4592c6dc87e910a6b1dbf85afe7f639189081954c5272a7af87fa3e82875590d4dcb" },
                { "cy", "ff1b431680f42365fcee85a701a6773e2fb2971b2ee9f8c9ba8bac314368092d42505e6568bfcc75656cd0b7a2b03dcb83ceebd65d97723c5c6027c3eb768f68" },
                { "da", "493f9e46814ef9600d6a5dccde338a08bce924aae2003dacd67d751d4c527a19ec30ba0442238c4a0aaa6f93918eab62aba6c914a631866dc661c770736dcb44" },
                { "de", "d682fb789bc197c2e3cbaf7eb40a410f3c6eb90ff235f52c1cf9d05fde1389dec07345304f79e663e40d20c0b3e0e5b5da60228ea8c07938141c0849148cb6d2" },
                { "dsb", "c76a041bf198284fd9cbeb6b70cd7dbb1fed800b7021a4cc4b2404e4cd7b8e6e69df71fca41a92cf89fe3b86595439e7e8fec3a9b02deacc920f088da0d4b5a8" },
                { "el", "0058e1539e09845e86533adda5bb15831a69f77ea315ba72e865dab3324950dc4209e784bbd040de1d49f411f56be8fdbe860d21b424473c5d295fd5895b3af6" },
                { "en-CA", "75245a2954a7ac47c3e37cbe51a6e8bc6f54de9f7628b1d080c2c8bc8fcf627a074a080ac24c43094b707a1a2d0be5296cac28f5cb1a859e222bd2e07ebde0f1" },
                { "en-GB", "eff70c5e0bd6c724f9e90d06de9c02ffe0970b4685b1215b724984170c151b4eade08893d59c7190eff97d0a5f3146db8bc83a69950dd43acb299c4a48ed0a66" },
                { "en-US", "80721d8b0281a834b217cbfd4b38e9a18d7110c615f2a49c2dc55d791860b5db929a99d82cd612ac91939f483b2393ce66fad7ae1ad0e14e0ca0a5d1b6ac7ef5" },
                { "eo", "51925e61e4c4bbf13e7fdc25fd14d96c0652b0b81fa73c890a0508e3125ac6c2536e42cc7be59a64605fa4be06610c3e02f9ed9dced43d92f4392b518299ff5e" },
                { "es-AR", "d447d65a71e79b1e5932e5ea57ba558ef764e45572929bd3caf48ec660ae8115e0f11c75c39ce73b09e41d14ed579ad9d57cc4ca88b8b76fc6f62e5702230a9d" },
                { "es-CL", "0e1a42a5d319fe662b61d5a12b6d0d4cdc2f5269f7ba705fee55c73921fb886225b57df84bfcb567c0f5a114d1cbaf4c8501cdbb7ac6bda52cf15b549c879867" },
                { "es-ES", "9c642fe84dd8f0e8585e57720d0a82c436e8033c01c18ff2eb40d18a773727c2e8eafc502974ec42b0d82186a7c7dbb60ae12fe72a4fcbbc46bbebe0ccbc8877" },
                { "es-MX", "01f5269094dbaecfa3e129f22beff37710eaaf3b4d0b8f94fe6f1478239b1bc2392aef41e5ac9a13d99f46b84927e613c4cd04b8465983aa9759b598b44c4dc2" },
                { "et", "276723052262265d48b39000a4ae15e62284e91a6a3d711b963a2683a34c6ae275c6c192106a94b4aa9df1f8375b3d98fd29a201bda4605ec928eb53f5631e44" },
                { "eu", "3ee767602c008599e8b5c39cbdd80a3c7d4f438cc62226ca60a9c1a17130468d0317c9ccecdc512f11947103dac5cbad2cb7e8ade57f056883342891ce91cbc9" },
                { "fa", "f58d22375ff70ec78aba1517ada69afcf1e6903d16c3894a7e7c4ffbbca83796c9ccf916efa9ff13bda4a1b8352631fb105175558a832539ff4771ec0fec3055" },
                { "ff", "54b89cdba98ff403d3e47995644a4472405d0b4642a5eff33c1e4911a183224a0396f6cc0dda697980f30f74911e13f97bd191d02ddbcc6a8f6dee82870ed3df" },
                { "fi", "961575fc88d537b81d4278d8dc8ad819ef90d47df60b99758b1c3727c80d1edeea7099912e57bca49a5c69055b4a8cbb43c5ea65a0eec5b50d95cc2ce31a9435" },
                { "fr", "024c4450cc0f471f54d47961b49f4508ee82957c79c8395430b9552abe42ad7964a3ff279018a6c60695c3d57346cf9fe3ce96898b13fbff83c27c4fa0df0680" },
                { "fy-NL", "b69e36e188de474c13ae6b12147fc4e3b5dee6076c83eab2fa46e05072117049aeb5304da861f6e041c1d313a9dfb20f2acbaef8d206659b462e5a87aee21f3b" },
                { "ga-IE", "444206e2d2c84cde7ed5e9793262bf74346b9c6160a1cd53d879f01c6f76bdf26b484abb703e575e988dd1c3bf3bd9bfee5d715da97ffbd83c693d06c5d8c186" },
                { "gd", "dca055cfc26f00cb9c108aebdb4cb1fd9eb7c1e02345d2bd8329a573f26cdf8e7290ad40abaf4ad3f8fadfeed594896412ad4e5d3d3e67e27c885f48058383a8" },
                { "gl", "c49af4613b97c5974e8c967793a2d89316b0a6ea091a2a6b1492c3512a337950c8a71c888c3ef317d97f2e82be02e33b31eb5f9019ad1a469bea72d099c78ab0" },
                { "gn", "b4268bfe5dd254d6b748f35759aea72d4b93e910bedc68253ef80218e4ef2139f5f32ee6ea6b5c8dd81277e1bcafed4cec6fe79acaf55b35b591a73d78b88c3a" },
                { "gu-IN", "e94ed7f517e30f86d77f3bc32123a9706e0e5f35bf703eb01b5ebf5af34a158d1d9b1fce82abf62ce3c02c48eb522587f5f0a7521d340237e18f178b69f6f837" },
                { "he", "7f349343b78d0977ec54c858c0b638d4f6e8c9c84daee6c9cd7f855754ad5ecb67888b1d98b16d2c5b43452de463d690a916baa9e1a44b92b40876d977a67517" },
                { "hi-IN", "ee49abaa1a0411ad5b8b96ef677a05bea789ca50b4f8c14939b24e3da2c60677461912ce2f58885f8d20f6cd9270f409ab81dc1f6a401f269e90dd6e175730b1" },
                { "hr", "824bf2dc59ddb6c2dc94b22102ee8fa0c710b4e25225762754b81fd1df6307b2ddfb452edfc8b52f930da3b00809e79fc003313d77555b2f395a65aba3b731a9" },
                { "hsb", "63eff7e53f0cf1873f80f5fb13ff7754e4785d3a94e616d334c8e501925deecd19b4ec5af6883c8fb0ae1226d68f77c5668ded950b6e0c48d1887a4931c76234" },
                { "hu", "442b94d52ef432a6246e16ebecdddd235fa1d2a5d46906064870bb3b67545aac4ea06d44817157c300890063fb9f4079c2073662aae6b559c25de2d2ec89ee4e" },
                { "hy-AM", "1ab30d8c14f594d249125b5751676b877514c818831c62bfe1c34bab62b04f80bfea1ccef4e1fee12353f5a5885a69fd2c14dd61e7ea9ad788bf44ac57b72cff" },
                { "ia", "d3533a89e89e8967a4731c41bbb218556b0bdb3228ccd7b3dad58267c9ad99fc5d9ec2ca7fd3ed700ad04c43c2cb94c4a955d795db2b4ce3127729b081a9490e" },
                { "id", "2b73651d01c73b542a4c01860f8847abf3c5e0c22ea16d14d3f44e6a0e8b55739bce03cd24bad2fbcd39551a59d33115fb407b8e15c5c51112a2dcf9101368cb" },
                { "is", "041445d103c606080a7d61611d9c39791e6480a2e4ad527ba58d575dfe70c74efa1e5b740e4146c7ec7d5f045c5d127303c82597893dbeea7ac6fa61d6970d2b" },
                { "it", "3eb4cc7a92e99995c4b19cedbdbec7a4aa457c2ab3632255a3a31bf6d632bfca7c0b7c5d3badc5448f549efc0c6c7901df327ed1ca0ea43ea418c21770be4826" },
                { "ja", "d7a841ab5d58cfa55b536a8a5816bd82c2396bb40116ebdd133c8135642088ace008c36d0d490b54a220a4211b6a6042dbb4ec3ae86bdc08c4a46cec5299a949" },
                { "ka", "3b086953e6610bbb60288a585bebcaf56d6e2a62aa63c1f6252256886df505ed033b25705b5ab8115883ded41bcc1972549b1de1fde9105d7bb12326594de010" },
                { "kab", "e3552328fc449bb2b118de5cb8443c6e095425e38716d29c97b72bfe2342abed5bbe9c1cd65b5fc4bc0aa79d170e5412a372c2ebc8bd4b7c96044a85a31e78b5" },
                { "kk", "a489329a83ffbf2e87b83e013cb217a5328821047b210f48e9498d94455e266e93afc9ec399045c2b1791769bb90115cc30599f792b09c070479f46e5aee24a4" },
                { "km", "ffa5fed5f0ebf2c456c45cd4b2c6c37239b2182f4d21e8a17035e8ffec24a181ef549183ec3947db0f61be86385e6e7d7fbcab3b41934d040f14322b22e26a77" },
                { "kn", "51500ecfaf18269c6518c6b765f2a853edb54bacf34019d787e38c6b6c7028a4ac15279065bdc12372eeb74242ec42799329c3ed05f04f9a1ee64db2ddaf26e0" },
                { "ko", "39988b4820c0f4f14fb544708eb6179709c139365a460e4ea115f7bf888ef3b9716a966150743d5a68bb9e1dd170e01bbd5a791fc1dec691420b2c00aaa0c68a" },
                { "lij", "36bb343636ade466439351a3adfb464d1e520b7c7840bd30bd91bc4f773cee9b2b99613cb3280a174c73447010e5fe763562b6fc9fadb476901d42832621d452" },
                { "lt", "c7bfd9938393061537efbb5873c071dfa8c1423e62e5facdcaac16c6f3f2ff598032dd1100828ebb8dce33827cfaf7d26c2a4ec5ab38d16bded22c89c4e4517c" },
                { "lv", "0a84b46bb61956081631c220a5c3c5f5577e7e6d55a4833598431d1d5dcb016f83a670efac251b370852fa4f1dba8d21604d8f5567f4c7445c6ad19a1880e127" },
                { "mk", "189869e726f11fb38eac2f5f57674eadc9d268e8698ff8e4ba5be0692c0b64796dc4cabb5131a78ad1fbd408f542b05751e637c607e555e8ca0e9eb0d296e25d" },
                { "mr", "6009d1d2cf0717dc930be707c0c779608ecd5773a8c92a2718ad1f4664913b5bf0ba8fc18d19b9be027967cbb7badea9418d5b3829d4c6fe4182d9f6153a2c08" },
                { "ms", "57241a40fa63e8aa90d8a81ef23c96c6af9557e92332bf05d3cdbd19fca9a3cec285ab104eba7d4cc742957476a4dddf4729c58dc66dc0bbd39400c5c947d31f" },
                { "my", "0878012044f5fe6277ea3f82c9d1d5043ca846087e8cc4715329e502e8b75d3f8061f93c5035d5f46e43141a239d2167f82ac163df804a81439094b0c8cf9faa" },
                { "nb-NO", "97609b17997be6392c7cde43b796c697d1ad611e5cfbb9e26d8053d3f300c7ea444d4a2007af3c780fd1ce2e2fa0c9ea5c9c9cc82c3091b246f94ff0552f05ff" },
                { "ne-NP", "f280699388caa4ed72adaca9197fe1d88a7e5c9dd08db150e16da14bba1461bc2944bf1153aa5495c9ee505f042ec9d6b371f2d7ca0033d727333c669ea6651f" },
                { "nl", "15f5a8f0e8c8c2b2f8e8ca0ed9851edf843745cfa08725ff18f76fd7479c8458e16c878d9f51fcba0162b3e687ea797013e456815e09997309f36be5934476ce" },
                { "nn-NO", "dacbf373891c6d65ba5e51def06c8aae0a9b8d346226ccec972c87700203129020414ffe351d140061b9d1e25b94f5afdbefdb4ef3c8567719b6e7233123cc8e" },
                { "oc", "b7a4f10265a01dd20f041f231d9ad8ddd8ab18281673502c117854ef9723cff08fbe8d3c5303916cf556ddbf31e770e83b115deb3065a0051b93d03edcbbf35e" },
                { "pa-IN", "7fa89b01bc0c17556f93b1c85576ef4e6dfded28568dae3932c415d7c9a04e11c10542582f7f023f50d32e1cb9c157cd581425f1b104c03e3e95ef0bdf41f2f4" },
                { "pl", "161313300b34dfc0751c07fd6787ff6c57ce4aff1f700d563bbec0a98903a5a9bc369d7bcd9f5ab7a6139eb1bffe749ddf0453e5f09abcd893ff8104a097b7a6" },
                { "pt-BR", "f6ffd81d2204aee9c336e1394ba6805558ad98c69b1e86961188a5403f95f1ab517e4a843b202b73c011edca0aa587ed4852b68b1bc1d5bd9fab738946264b67" },
                { "pt-PT", "3cf7dbdff482e0c4856b459496d2503509771b9ecc7fa1d23ab91ca709fa0d2a8f0b58458bda40c56f49b705b60bf871143c369659897252610373852df2921c" },
                { "rm", "0893d5f918b1298fd864bcb66975e81bd97c36aa57f9dec936e6df859590393c025f8697b83901a5a1e36370683f7df151c47d4b91700958bea60523c78b056a" },
                { "ro", "23d6416ee7ed40d7f71176865ae900fb739f10083321df38dfc7830782bef113413fff1e736805e579fbd9d619d81e3232e666d47eb774788ad5a9f6986930bc" },
                { "ru", "7bd7b84edbaa63075ee5de86abcd3f4bf496df62d4d189bdce68a5f4ad7e682fc4725c6088cd2d88a966970482dd0aa7a40bc67a560b87a217a792a7e2f31545" },
                { "sco", "dc0c17e5cf9da3cc3fbf285e6ec4dccc72f64eff2f283e5640a1f75bd42292928819ef216aa7c0d2ca53423371f5abc482f55cfdb19aba1ca2371d0ede8c79db" },
                { "si", "daa7665c392db9042db0e0189ef33b1dbd17c761eeaab06eb71f093452c39d466e184e7f327ac943eced64b8f4263d897631adca271b5ab7a2c0823eb71dc8cb" },
                { "sk", "41e42f35a87ac422e84d93cae410be43c14d0489f2f1fa8bf5d5751483178418c50863085b095e983bfbc233f13130a29adfa6502d74a6cdffe388d03b87365f" },
                { "sl", "2dcdb6f02aab0bb1cea75beaf7e1638d02a1f1620b92d4b57bfe1f46948e44cd1d662af0cb5ac6b2f77d5814aecb7b4a95eaab43307c591b6262b9809a87a789" },
                { "son", "55295b6416ace23bc4eff2bdf6399402d422b209069acad1edbee2b5b40b4c65a96a2cd1698e0b9ac40c69890501789d63591402b2fe65b1c0a5dc1b2eda6f10" },
                { "sq", "6c3b7877318923f7415caecbcc38c3341de9f84d3f1cfb98a965e1dc8f57cb7387a6e30d7902dce3c514e0ada2b334ed0a81b1e799cdb88bb6730f3d5de5f0f9" },
                { "sr", "435c6cdee9d7fa725d8f04df8d8d58c927b3ba58461d15532002dc3a9d87fed694371b3397d20e8cea4a25f15177e4c0a30564529044bd86355af84dcabd2f5e" },
                { "sv-SE", "2d582374fc00da405fb73e4494474247de28c1171a08c18682fb423b923c09637e97b9f4c0b76bf0d0582ca4bed47710127a9795d35a6970f8534960a8e61be6" },
                { "szl", "3ca660608a070307aa6f925732a09dc611c1ccf1b1f576b5e5614d9adfa9ccf62ae548263bb9b8bc4bfc7f906925ffa039d13079f44e49800b14a11c921d8ddf" },
                { "ta", "94db18f66ee65ed5af4a5b81690bfd110b321c3cb082dde495c9bdd666c4b1765b57406c2394c337d6518f8ee21cbc3a9629115c8705514e678da164131fb599" },
                { "te", "81573da1712415f2919da73630ee15a04cd17ea8660b7d2422ec053151056ad8bd9c1d31599f56887e48cffda3851b6cd89930f5688e97087397264c3569c4e7" },
                { "th", "44659b13641fc97d9c46e1924e8692f3a7f6645c278395a770f87cfa0911387c3b98d95f0c725ff6b586115ab64c864988d7d0b8d8afe632e9730c8cdd9477ed" },
                { "tl", "3957a3eacf2b39c390125f371d6f78f0e20956fc999102cc4cfae633604344d80cf8f60ddc2a427e451847cdb9eb33ea998ab954025abe522bdfe71239f0f084" },
                { "tr", "f513ee44f14242f23e18f087462bb09bcccf13a0ebad1f9b7d04cfc9d6b5ec9f63c1c4d1e6249ac11f2ad66663924cdf1f8ddf3d77b735ccf4d72b547dbb443d" },
                { "trs", "4edb428ba45bbd261226f5a4c4df184e9e023cd9a30ddd6fd0debbc1924b2765a1b83dd4835ce4b4dd06e5b5c91abedb597da83e00aedb2bba8395f4c2a11fd3" },
                { "uk", "049f5c53c7f171a7c9bfb15f786c2d2157c7b04a32effb9814a518850cf368f23ed168cd23640819994ba4ec9c714a379a78e563adb719185db83dfb910f527b" },
                { "ur", "4de02721a9846bfe2b8400574b0ca6b7e1ad520ae67d87e32d0e44d974e76fae044e3df5bde0236b9304b58468f07aedfd1e116bc291152f77e6a527160fcb6e" },
                { "uz", "3aa2c144e4d3a0e52645ad7326e879c39080d23fee683a3ff4044ea68d93780066c88058b54be9f3843e9729f135707b9e8e27d4d9ad1ec035676140014d7aa3" },
                { "vi", "9981b91dc280a7e7e1502d3717f8a1b89d73e89ea3344598e60a86e562388becf53caf054c6b43962b9d54d77e17855ac65df8d48d0f3c848738f8e0de161de0" },
                { "xh", "c6d5ef8b55e75931fa48db6521fbca07c2fc439298dfcf654e02ccc3fd217b3c7cf5bcbf2abf004bd091ed6dd738154c24fa925e06bbe61b27d7cf0acf3a7454" },
                { "zh-CN", "f3de91720f7e3012e424d05d92fae96c63738f7846c0d702b37dde9b7bfb595dc54f5ac232121e754d7bfb761ea56f7ce8e74781a7166d87b3d777dbe0b4fa8a" },
                { "zh-TW", "e4bf6f3ab7a3108cda2b02ebb8c0a22e6ae8fa4a2be37a10560e21806aaf514d058f11ef894e8e89b4f1d801c7d833a705e5d7c31f72e66305e30bf9477e1888" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/102.12.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "4f2ccc8f42c82a1ccee1e9cead758bc9a7f15afb999a51e4094a6a2f390c6d68d474c0d1dd7e897bbed423b3084c80325e28cba8d77f79b4142997eee4905a59" },
                { "af", "92df1729494c9a7c87f9f32ade3182949393bc69b08157e7fb2834d7e1433f4a24d74aa151aca5eef18b69683c523be93c1f2ce5429821a3c84c835b01a30d10" },
                { "an", "0ffc9556e43894c5ceb50dfaddfe04af740ddab8a3a367a3d54358d9b7272b446badef0185fca66c20846f483b1412359c21ea5c1444bad621dde72c39259bd7" },
                { "ar", "0d3300b7dee625d445146d4c2d569f4a9f207ba67c3dc1058b71e90a0be0013e641c2235be22192a33c0ebd285210892129e7d9239dd27de4b6512392371597a" },
                { "ast", "90a6de276b654185f0303b0518987a51d038a23870b05ed0a40f51b6f07cf9cefb60d76328bf8409b455f1fdb595bf6fe92904ba756fdb8cd9cab82d0367b6c0" },
                { "az", "fbac776639914fd2e955965222d2482f6d2355de06e9ea2b6e35dd880cb7fa4ca4a48adb7960bb48d87b23c466754a2050e491c97631464408ceebd191a888f4" },
                { "be", "d019452ba587c970b14735c027e577c5cc5d9e1112e8895948329ba295204c87586ed12244e442d2e10c10c9b49823ed9368c6c28a283bfd6648099f8f13ec4b" },
                { "bg", "863120871d04575cea4c52507f3e4a55a7dd84eed4a0f3451505864b8b7ac96e80ebd95f3bd1b0875da884f0bf7e958388cd14acf1423035139a6f163e5f6049" },
                { "bn", "f1c01adb7c4395a261c057adc6ca02f029756431787c000796592f4f3d20b0055efb91020aa6370321c28d3a261aebb8e9808ecf27a5087d27185502dd45d475" },
                { "br", "ebe3dc6f64c5e91d8d6a1217498203423f7787c9b0f2d8cf24d6ee796e0fdc19fc0ca6775ff6a3c867f986aef39a357ccead20ea76ab1f3879ccb749108962fc" },
                { "bs", "a300f44156b31e3ae0c41884a51327fab9b862d258950336913cad18dac829ac667e4192d1f5d1131ce345ff6a464c77675b29636e42800b849b825f09342012" },
                { "ca", "f85e4ee4b1f892ed65db2e72660856a2a393282d4ce12161d69de77c54be3a077058e406b5aa8f71588c30713fb24030009055c80dedb3201ee59adf7576c6de" },
                { "cak", "3516dd1ed247007e448556222d8e35aa6f04bf257c7b65fb529cc10c3d19e525fb143f01374d91784920aa96fb722f3a37626c268ea4cdfa27a32fbd74683396" },
                { "cs", "0a1b0ec99b08e2dd1787610eb42a3d66a304a0b4dd39450e75915a8460cc023136ae4105cd5b0cb1f87ab145531bfb7e4b1f36ba13a65d948d1d36d75c5c5526" },
                { "cy", "f0b967c961adf1e464747a456ae8ec7873b24172cf99a247d8ccf2b27c1bfe81f818be8976a26f2c9c52182d4bb71864f19d87082dc67be19785318198261933" },
                { "da", "12a3a2a61508bfae8677d16bed454e4222727eb30b7c83cba474cf7783531dd498120661a2f394afc1ec99994990ff0043f66a09d14faff31edcda24c59fd7b2" },
                { "de", "11c165ede7c58f847db6e5c5048ecfac401257479cfda96ca0ee69e553ab407299416f64c49aabf5c52f10caa793018ba596044f867af751ce53ef200d52b641" },
                { "dsb", "c9f5d54742838c94fb5d75d0562edf80ba9ce287010467ab984b082e4c74007df197c58e268cef7230f6a76c5976f61810f6c77d59357d0a41cf3ee53d12dd9a" },
                { "el", "4ad78f660eaf626cd255dd90b8d91e79ae8a8496bfc1c641e7828d6d110c2fe321f619cf19e2ca8de6b537eecf77eee72262180ae8f4442ff09bc77695b86ab3" },
                { "en-CA", "a20d2bba866793e5275d19d433bb565976aec5b7615970ed7d715d393750678d1c6259335b270735f4efa2b4aaa5e49ca54f523ea3991296a985e172f66d0d5e" },
                { "en-GB", "7c7b722cd99ff2b6c9421a6a4d964139b2a4be5e42b664f026a23d7e795faf9da0c37fe708150e7433bfa1d8e27e8506bf52e330d3ee4e9448c28612f8a5d8f3" },
                { "en-US", "0b90d341f218d67f210ec954b24fb5da07e75e78020311f184257855cdc7ffb155d29a18665cf2cf9434dc2519548a9f988a601bad0964bd38c24e6553df9d5e" },
                { "eo", "31beaf3a9042add5802c07f1b31f16cb8d83ea59a3b4167058a1c200554402ad01efbd8dbab2cc4d000f4d89a89d9ec5ed388b102bfaa1ee41943da1e05528a1" },
                { "es-AR", "50ba1ae461928528f54be199330d04b03c923f5c731ca37e3ad0e26ab3df3e4adb3892ef7cbf5718de1b449d63f2e5af8a9ae870f6e5f4b3a4ec168c55312b96" },
                { "es-CL", "f92d2bb48f25db6737721e184d738a1a78eb7f9db83c16e411a020c2f5cf83718920a4e234d7c2946d9d4ae1380e64edd9ac560cbdc05eae86fac64bc6c450f7" },
                { "es-ES", "16186174468c616a68726098dc75febe95944c07cffa4dcded69eff15e520d34064a90cc0057dceba3a37b9c0c6766fac26ffb8d84c650bad17a2d619f07eba9" },
                { "es-MX", "cd843208b91ec23a1e292d970f1bc8886139822f6d4c452219d32097f96a7db2541d54395fa9a85c626f8f00adde1e50e15ecf1808f13f4d093c933fcb37c364" },
                { "et", "6bd83e61b29a4139504914d43660281d2d88dc03dd4be117890949e13f22e1d5e1d73bc3579291b5f683f1872b58170e59bcd32e51f6f4cfa4b3e01a08a68e33" },
                { "eu", "d134d16572e7988b4b88ea0c7dd9d019965c424fd8e47d428248ea47ce70a99478ef579793d8ad67a21045751a26b069f80d55ca91506ad93828e35437278193" },
                { "fa", "cb5880391fe937186486313779ed776ee03ab15fea0cccb9674d2d91e170187deab3b145797fb8f10dc25449b66bcd72d18e758bd51d3bedd2e84a80ea240330" },
                { "ff", "18658824c687231c7a2f765bf9f58c318bb1eb297637cef5a12a55737ef9571783550aac310ed4aa1b20bf985a7f376c193e04c3d32bd891f95b58af46107ab2" },
                { "fi", "14144bbb53c638b7940e4b3ae1d0cf50a0d9b18559c7088c49fe1fd5df800c4b3db4de693fa3375fea7a0f4086e0f99c5a243859aeb23288a7e8bc7b126eae96" },
                { "fr", "9742847a7e0726c80149ade880fffffb288749f71d73e68b60167a40b87da722e4c6c1e55c83cb99ba74d6246522de5d5441c88b9d9937e87e1024f9043dde7e" },
                { "fy-NL", "c52215e5ff509689c5238d1e31e5283953505d56f0a6b198685d15f1c89c6821261ba5679d0318fb6b2886f835389ff26926ca3f7d37a7fbe27bebe627f5af96" },
                { "ga-IE", "bbd89ed30f3c0af0e45489872423dc5774a5d8fe8ad8e0f49d543083a13ce16f15aee39c3ecf538c26b78717da5c97a005e04b1974cc490e4110d4ca9cb45185" },
                { "gd", "7638a87effbdc31b018b40a6776cd66eea8e39a57000783e3866a39431a81af5dc5126de2a53c53a4c66de20588c49b33c2320f29fa3834a2e838706b3a91c03" },
                { "gl", "51b28eb5524104b2c00c567b56b11899066c1f1494b70cad7962ac0e00d33b544fe851a308cad0f98e404b0d4b782ad38e1dcb4a0b27bd22d3c8ef2b959269ba" },
                { "gn", "b89865c20ed3244c05b662c488c73a504f06232e141e4b1c569697fddfd2fc166e057de253a12d97830ad86f72f7e2b47d29ca4459c546e2e5e45868bf37cbf0" },
                { "gu-IN", "3d15097d497af52cefc6246eeb8dc299ed66536dde23e9d22bdd1854f228f7a79f05ca39a56605bfb9b59469d492254ef19859354dcbc74ee29f85e2d44e6298" },
                { "he", "40280a8d76d33901a0914ce76bdb822642df0e0bbc10adf2115b4dee5e31dbae3a94e1d5d6177660640673c417cca61084a9190fee8ced6242b46e8316ad4e77" },
                { "hi-IN", "de841fa0c4e37b9074da829ffb6ab46752baacffe3a0b45316c718947700962050681ae946c380c353547025b396600cdd5b76b125223ca3f6eadc10d6aa17a1" },
                { "hr", "acb90db2aa7fd08643a2335d1ade4b1092af9d28c2279592e9ae48b924a2a2b81f5963188335b6452edbb864fd89460089ff0711b911c5f8fe335b4b411017b6" },
                { "hsb", "e31d05110e2c4eac29875bcaa82ebfb4ac516d7ecda9c3f40f8e4fa4515d96e8c48d88118c01c941b7d94e70f93a66ac4581521958e3cb19446dc1f32f64515a" },
                { "hu", "7dea0ee3afa0d86a2d40a4fe137c0749afb8ce13f1c3d6cc6aab289b47c65b1b8c67c018ce2d2eba3449517e9b9ff462a78f8d7b9fcf278105a6cf70dad977ce" },
                { "hy-AM", "3f68104fefdb8203e6a582426fde23ed1c1dc2062a476e832156c33e634cb61add000c80cf5d816d36b437aeaa8b16fb1f03f28fc730193a4d66d926e4692d2c" },
                { "ia", "6db6d39e9f6141665b7baa7f49f41a066aa269bb6ca32a539e9040d08214f558fe5d6450f1203338075bee8d8fb9c1239865c075b91a748f0f738a43675dae88" },
                { "id", "15680be519b241917635cf223e920f6b60dc1231d78c30cc3133337ef33f3c59da0302c06c058a4dd6217ed2c56f8f05745653b96cbedb6e6e367888652b94fd" },
                { "is", "0fbe0a2600d0d5b9372b7d8435f816535533430cc1c57b9acd388759c8f11496c89dad3883bedafbe2a41a0620546b861c6a21ce80c8ac278af355d6daa4561d" },
                { "it", "8f03f8f14256c37954918f5b85381b26497b4f3bc364b0d387971f23f8d2b766ffea1301c4b7e0710077d6a5266701ea5a5207e69b974b2d5cf83cd7a7b7c6f3" },
                { "ja", "8514a3d3000dfff7aa6cd1fde50646e34f2d1c253b86bb2638814a4ac622cab1bc8b71a6d9779a9eac662a59b290eaf0492524be3cfae60543e48f366203877a" },
                { "ka", "0e2bbbcacb72ef755797050c2ec6e92da4a98a33c515b4be3b4953d2a32d68852aef6a837a9f36a879cedd57b2a38a2740f8dbaf14e94281f137203d2faed660" },
                { "kab", "b6385f8c563582d2f9b322fd9980965636bfa7241b1cbc02024781bd2c852cba22784f3a6bb92e85e2d8c91422ab2bb3820b8822f8e1e9a8621995b865e74e53" },
                { "kk", "c147974497803552a36989977dbbbb7639340b07fe6e91feab4df5a4c5235216e700daf01b65a28a678270e3fb92a3a9c7c4afc2d27db6ce345473191913b08d" },
                { "km", "4020225607656fc754df9446c0a64c42be81879f8d42da7cc66175be40cab06dda6ba77069803d350ce4b0a72f505e49b1de1bb81f445b85a4e7357379ffd4b4" },
                { "kn", "6be92581d4a2be636abbd3b7593ced48debc9d2d00be194d8d39941b4b531acfc0ba7a03a3af635a9ee519429209ce874ff2a83ce8077388a77c3af354ac3f53" },
                { "ko", "b3e8ccbfd8a8db1ecf80dbc54d1e56a6fb133643f852d56e3787bc2e9737b8af407cad1dd8c449779a78301461863f282a0d3930c6d6ce6c60435d255a29c4c4" },
                { "lij", "3c170a172ede6ba3ade6c1677320536f0c218215d1db29e01b7fd17c3c30f3af083f309fabb6a4b080af6a73f715a9f55d569c9d6fe5fef23a752f83722e1750" },
                { "lt", "c0244f27e170b001ea1e30f57d061886daf874e62418a3c39af34bc44b0da28c7da62628fb579b8d68a74cc94fbdd20ec6ab056e11378687a43e999c56fff962" },
                { "lv", "471966d548e6712927c0df118c0afe3c9e9a4739ee0712eebf68efc0c5533095168ffa8c85f33d37c29650878c48f1e53dccdd81ee70b00c4adce972568f01e6" },
                { "mk", "f692c1287263ed54fec739a9970528285d329c86f602f1d1242ea5b2b9722da4c8c45cdd57965df1d7f1deb0b1d30280f0791cc9476e396eedc2f1ce11401446" },
                { "mr", "ffad16967ab942369dc3869f4fa094d8dd7c3b941ed1e276a637468efca4ff9bfb1f1939b027ce40d337b7b9ce2b807255a67cbd1e98b53054aa4ebca53ccc8a" },
                { "ms", "fd9dbd87d37a21b4f80f772ebab8e64634c0d4a2b14b43ab3339421f8f52a377fb3434b07fd13589239838f167942b3f002ed5cb82f9dfbaac8557f5a61509f4" },
                { "my", "0bd710dbe4a04555ed3bae23fd68aac23b0ec73a6957cca3219bfd167fa883d5f67c7058d90c2cd97f4f2759c3240132693fcb63aace588e121583214b7b0e4d" },
                { "nb-NO", "da908e027c417ff48bbce1520952c91c1d046f55ac38d7640aac0e2b11b15e684989d6d9961f3e00fe952dcd6fecad1653a1f5dddf52e74419ea02eb48e3701f" },
                { "ne-NP", "cfe3acaace16af9a2d50d32551ceac36f1338bd9aab3248cb64cf00172366025159543f928400ccf266b22c02fc091023f5fcf4e895365e2a757393c0284f740" },
                { "nl", "ceb229320d67b53420d2c501a2b1cd9e103dc2aee164277ae0394728d85d6fe999ca917ecb8bc190fcf27f54fca7a49e62d5658f4849c0d1deaac1fa0fb45427" },
                { "nn-NO", "763df2886fcd3661e66563660c3fa6e5b6368d722b7908503c9e9b80e328401daadf11ea8f458d956209bd3c577397242c1f6709b6929023c6c71111c76a8bd3" },
                { "oc", "63fa67efada316e610afd68879fa60d85551e2b837dd664a5bec334733f3897f6dd54313b5c0d2d8264dfd59f6977c3b6f95f87f0dda67967365b72dc8140e2a" },
                { "pa-IN", "45dbec93a11320ecf5e88621f7ad4fd7cd75c838bcedcc2f54eae8377fac9163f09cae7cbb418d52470f0a4655c1095cbc6b5a47578bf2cf0b74593319ab6dec" },
                { "pl", "0ca21ee03affbc24faeaba6b127c08b491e9b9a60041c00c815873a1b85439a30a7b3664fc2c6e12f75d2a11d80c8898dd203b32471868b1945f3a54fb25aea3" },
                { "pt-BR", "fd6bf30a3acea5dbd738d44be9728a1122294deccb535689e66de447b4cd4b8d7088cb5a9b9961e764dbc64aebb598d6f7f5f36cbb3e37131484c2360e37ef7d" },
                { "pt-PT", "a9d58ab2e64c6123a3fc5a404c24295a1b1edd8ae55182aa898ae9858d1d8aa33c4d32206e99c12318084188e1d870ef4288350fecf48dca553cea845e533469" },
                { "rm", "a7ab4d1637ca08dcda48c9dce0e40a0d95934c51e44ba8f82da4eceb5109550ad9779357f47f927fefbd1cfe39e723a52227481c6b296723c1c1929007c9f6b8" },
                { "ro", "96a79993e230afc0dcbfa2c7e8fd0a0999aa00966c335b343d6d2b0b90ce93b9b94f688dc2ed847c01912d327f732302cd9405507813c62c9b722bef2927c5c1" },
                { "ru", "c82035717780901b14f7d304b9f1f71bdd4eea1bac15035b40d34141cfa5f18b653fac5f7ba86590503603301fe1572b9d8a4d3499977918de94ba928e51bcf3" },
                { "sco", "1b803ac525ee4b824e0904921b839235c48aa1a9809142d1dd645f87d47c41c68e5c1c567965014e289b70f7472069a59bd248a14f26dcf4bde2f6d005efd365" },
                { "si", "a82dd1d8f554d837039759b5514cffa972841c92a5153692c8d58cf94c4fbbf47ffbaa6ef06ed62b8be56fe13948dc5be9b8baa900a55a4ecfb7ef942184141e" },
                { "sk", "83723d8e32af8b9f1100c83a0fa97c80fefc482ff22a3c58aaac4ecfe9dc42c7ddec1d93c1e9c4321a30555c0b7a1a29fb5e8b9401d67ca80cbc14a82ab720bc" },
                { "sl", "3e40c94de7c8f67a7a9afd28fb0d60af3c06cb29cf9637b7e17f818eac4166684c5dbd78723ac21177a0c61686079b601b8ecd3547d384f6b11219c67be0c9a6" },
                { "son", "3e3ae86e38a3e768d20bf70223dca89471004102e828773b750d6cd354ec9f78498f6cc9ca288d46e2b7f62e4fb25fd41f26b2144cda426485174b94a9e9f161" },
                { "sq", "f77fa04cc4b6127c3b31c615f1fc46e8f4269be6ebd141af96c4c1cbe46b1f365f9ababeedc47605fafdf2f4022fa36aac6e476d086cccde9981cc7caec72dd2" },
                { "sr", "25e42394c8beabe0c0daebbc24d89d2b7f72a395ab15e5156fbaa5fa1d9e630ab15ac06201ac8d7d1642f9d8b04fcbdfabeab7e98963ebb7f06b981c6e955eb2" },
                { "sv-SE", "f28f0c62028a5bd03740a4fa8a7d78dbd11ef2c8a2e8d53b3ac9440d1b2b196586335b269382a9a88330e5528be03be5e8f42caff619b41f91c1c0884ddbd139" },
                { "szl", "62cf21ff0fa80e2dcaa79a267675911d41f09db9b999da82dc2b1941ead54defea76785ce12d0a18d3d9620f5266a7170f45e83c925f51c286b4f775a49a4118" },
                { "ta", "6b16842f1ed9c4b11dc2578efc7205b391af6538068810913262d822a267526d5391a58380390fa6b2cb2bd188dff9841878f77b0fca95e9f9b81ec4d8b10d4c" },
                { "te", "33222f44a624e12cfb824645c8d83cc00012a235c4c1b21385a27440f0993290165d0b965314f23ee6279e445748e212588b173847f866ffd5e5da9de2c5c6c0" },
                { "th", "2a1b3f21e3e889ee69232525024f412d463f5b37278fd63ad1fc754e682d36403d9f2c8bd6158040c4a92a8cba8731d6edb1adc22bf436c158fbeb15f4cee116" },
                { "tl", "597b5115d5e64ed7fe5f640748bb06ab942e26f2fbfff548f519d81e011012dae6f8d471556e201a5e32f706d43f74be04d922222659b548066361bd6702de94" },
                { "tr", "35aeb2c78ddff9aa3fbfe9fd90619abdbcf1e9905fb3244f0f49df13d5070cb3a09e861e0e9998ea7203c7e72880ea7830327ebad5c0ea843c437f136bf7a11a" },
                { "trs", "459abcbe60e4e05db55cddd585335361629e6a08da549d102df5a27d014d3b99939c162baa23bb6e437123261d999e0bd3d10af37a1c7866f5febb0e5459a4ba" },
                { "uk", "3ccafe17e64a13590fa896af7435486d43908f8dae46296c5656ca424f936ee822be9aab190b563adb7afa34450f6ab47735c6b92dff08b30dc1756ca8caa4be" },
                { "ur", "e124c5a02d71326053fe47f75b29b95842598f4dcffa69806170345b3a5db9efca11415d38ccffd345a1cf7bff1ae1939a2c59565d663e6abcb2a382dee91dde" },
                { "uz", "926bcd9221d71d7cf003eb614cad43ddfa12f7254056ebea6cc464f91da45552d66770e92112bb591d23ba8a52180a6c65bc1edf6b873fd652ea88a6b1899e8c" },
                { "vi", "47fd7ecd84a988877bf352c867886b6b36e382d61e2180ee09a53ba349cee41d65153e3c916d50aa010935fa59162db719a0e048be2d2e2d5b3d0606a9925b7c" },
                { "xh", "98bf7114eed8c1b87e83238ea60fa7801cdc6460cc4dfa284582e7183947a3c8d2c648812a09de45df001655ff80403f5900f231eba82327c7a59b884129fb8d" },
                { "zh-CN", "2387c3cd47794b609310e14bf41a37dbcd9c5c0f14b405fad6d860dc2473fd16744f8ba6e5bb972685e5c86f2e8c388271c8e933e44fb1f752391383716fb121" },
                { "zh-TW", "f6a293f5a7c9f77a14525e325db78900c3787dc8f498333cbf06f5fae4a353870388635b7edad3f0537282405720eb7032eace4545ee8a000d5e8bdf26a42765" }
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
            const string knownVersion = "102.12.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
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
            return new string[] { "firefox-esr", "firefox-esr-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox ESR.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-esr-latest&os=win&lang=" + languageCode;
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
                client = null;
                response = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                return matchVersion.Value;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox ESR version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/firefox/releases/45.7.0esr/SHA512SUMS
             * Common lines look like
             * "a59849ff...6761  win32/en-GB/Firefox Setup 45.7.0esr.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "esr/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version for 32 bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128] };
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            // Firefox ESR can be updated, even while it is running, so there
            // is no need to list firefox.exe here.
            return new List<string>();
        }


        /// <summary>
        /// Determines whether or not the method searchForNewer() is implemented.
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
            logger.Info("Searching for newer version of Firefox ESR (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
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
        /// language code for the Firefox ESR version
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
