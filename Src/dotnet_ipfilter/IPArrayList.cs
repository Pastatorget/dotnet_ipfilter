using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;

namespace dotnet_ipfilter
{
    public class IPArrayList
    {
        private bool isSorted = false;
        private ArrayList _ipNumList;
        private uint _ipmask;

        public IPArrayList(uint mask)
        {
            _ipmask = mask;
            _ipNumList = new ArrayList();
        }

        public uint Mask
        {
            get { return _ipmask; }
        }

        public void Add(uint IPNum)
        {
            isSorted = false;
            _ipNumList.Add(IPNum & _ipmask);
        }

        public Boolean Check(uint IPnum)
        {
            bool found = false;
            if (_ipNumList.Count > 0)
            {
                _ipNumList.Sort();
                isSorted = true;
            }

            IPnum = IPnum & _ipmask;
            if (_ipNumList.BinarySearch(IPnum) >= 0) found = true;

            return found;
        }

        public void Clear()
        {
            _ipNumList.Clear();
            isSorted = false;
        }

        public override string ToString()
        {
            var buffer = new StringBuilder();
            foreach (uint ipnum in _ipNumList)
            {
                if (buffer.Length > 0) buffer.Append("\r\n");
                buffer.Append(((int)ipnum & 0xFF000000) >> 24).Append('.');
                buffer.Append(((int)ipnum & 0x00FF0000) >> 16).Append('.');
                buffer.Append(((int)ipnum & 0x0000FF00) >> 8).Append('.');
                buffer.Append(((int)ipnum & 0x000000FF));
            }

            return buffer.ToString();
        }
    }
}
