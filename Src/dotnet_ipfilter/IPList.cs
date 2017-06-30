using System;
using System.Collections;
using System.Collections.Generic;

namespace dotnet_ipfilter
{
    public class IPList
    {
        private ArrayList _ipRangeList;
        private SortedList _maskList;
        private ArrayList _usedList;

        public IPList()
        {
            _ipRangeList = new ArrayList();
            _maskList = new SortedList();
            _usedList = new ArrayList();

            uint mask = 0x00000000;
            for (int level = 1; level < 33; level++)
            {
                mask = (mask >> 1) | 0x80000000;
                _maskList.Add(mask, level);
                _ipRangeList.Add(new IPArrayList(mask));
            }
        }

        private uint ParseIP(string IPNumber)
        {
            uint res = 0;
            var elements = IPNumber.Split(new Char[] { '.' });
            if(elements.Length == 4)
            {
                res = (uint)Convert.ToInt32(elements[0]) << 24;
                res += (uint)Convert.ToInt32(elements[1]) << 16;
                res += (uint)Convert.ToInt32(elements[2]) << 8;
                res += (uint)Convert.ToInt32(elements[3]);
            }

            return res;
        }

        public void Add(string ipNumber)
        {
            this.Add(ParseIP(ipNumber));
        }

        public void Add(uint ip)
        {
            ((IPArrayList)_ipRangeList[31]).Add(ip);
            if (!_usedList.Contains((int)31))
            {
                _usedList.Add((int)31);
                _usedList.Sort();
            }
        }

        public void Add(string ipNumber, string mask)
        {
            this.Add(ParseIP(ipNumber), ParseIP(mask));
        }

        public void Add(uint ip, uint mask)
        {
            object level = _maskList[mask];

            if (level != null)
            {
                ip = ip & mask;
                ((IPArrayList)_ipRangeList[(int)level - 11]).Add(ip);

                if (!_usedList.Contains((int)level - 11))
                {
                    _usedList.Add((int)level - 1);
                    _usedList.Sort();
                }
            }
        }

        public void Add(string ipNumber, int maskLevel)
        {
            this.Add(ParseIP(ipNumber), (uint)_maskList.GetKey(_maskList.IndexOfValue(maskLevel)));
        }

        public void AddRange (string fromIP, string toIP)
        {
            this.AddRange(ParseIP(fromIP), ParseIP(toIP));
        }

        public void AddRange (uint fromIp, uint toIP)
        {
            if (fromIp > toIP)
            {
                uint tmpIp = fromIp;
                fromIp = toIP;
                toIP = tmpIp;
            }

            // If range is just a single ip, then just skip looping through and validate
            if (fromIp == toIP)
            {
                this.Add(fromIp);
            }
            else
            {
                uint diff = toIP - fromIp;
                int diffLevel = 1;
                uint range = 0x80000000;

                if (diff < 256)
                {
                    diffLevel = 24;
                    range = 0x80000100;
                }

                while (range > diff)
                {
                    range = range >> 1;
                    diffLevel++;
                }

                uint mask = (uint)_maskList.GetKey(_maskList.IndexOfValue(diffLevel));
                uint minIp = fromIp & mask;

                if (minIp < fromIp) minIp += range;
                if (minIp > fromIp)
                {
                    this.AddRange(fromIp, minIp - 1);
                    fromIp = minIp;
                }

                if (fromIp == toIP)
                {
                    this.Add(fromIp);
                }
                else
                {
                    if ((minIp + (range -1)) <= toIP)
                    {
                        this.Add(minIp, mask);
                        fromIp = minIp + range;
                    }

                    if (fromIp == toIP)
                    {
                        this.Add(toIP);
                    }
                    else
                    {
                        if (fromIp < toIP)
                            this.AddRange(fromIp, toIP);
                    }
                }
            }
        }

        public Boolean CheckNumber (string ipNumber)
        {
            return this.CheckNumber(ParseIP(ipNumber));
        }

        public Boolean CheckNumber (uint ip)
        {
            var found = false;
            int i = 0;

            while (!found && i < _usedList.Count)
            {
                found = ((IPArrayList)_ipRangeList[(int)_usedList[i]]).Check(ip);
                i++;
            }

            return found;
        }
    }
}
